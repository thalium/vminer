#![allow(dead_code)]

use crate as ibc;
use alloc::{collections::VecDeque, rc::Rc, string::String, vec::Vec};
use core::{cell::Cell, fmt};
use gimli::{DebugStr, UnitOffset};

mod relocations;

trait GimliReader: gimli::Reader<Offset = usize> {}
impl<R: gimli::Reader<Offset = usize>> GimliReader for R {}

#[derive(Debug)]
enum ResolveTypeError {
    Gimli(gimli::Error),
    MissingAttr(gimli::DwAt),
    WrongAttrType,
}

impl From<gimli::Error> for ResolveTypeError {
    #[inline]
    fn from(error: gimli::Error) -> Self {
        ResolveTypeError::Gimli(error)
    }
}

struct DisplayDwAt(gimli::DwAt);

impl fmt::Display for DisplayDwAt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0.static_string() {
            Some(str) => f.write_str(str),
            None => f.write_fmt(format_args!("0x{:x}", self.0 .0)),
        }
    }
}

impl fmt::Display for ResolveTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Gimli(_) => f.write_str("error parsing DWARF"),
            Self::MissingAttr(attr) => f.write_fmt(format_args!(
                "missing required attibute: {}",
                DisplayDwAt(*attr)
            )),
            Self::WrongAttrType => f.write_str("unexpected attribute type"),
        }
    }
}

type ResolveTypeResult<T> = Result<T, ResolveTypeError>;

/// Strongly-types DWARF attributes
///
/// Each type defines the kind of attribute it expects and how to get its value
trait DwarfAttribute {
    const DW_AT: gimli::DwAt;
    type Target;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target>;
}

struct DwAtType;
impl DwarfAttribute for DwAtType {
    const DW_AT: gimli::DwAt = gimli::DW_AT_type;
    type Target = UnitOffset;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        match value {
            gimli::AttributeValue::UnitRef(offset) => Some(offset),
            _ => None,
        }
    }
}

struct DwAtByteSize;
impl DwarfAttribute for DwAtByteSize {
    const DW_AT: gimli::DwAt = gimli::DW_AT_byte_size;
    type Target = u64;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        value.udata_value()
    }
}

struct DwAtDataMemberLocation;
impl DwarfAttribute for DwAtDataMemberLocation {
    const DW_AT: gimli::DwAt = gimli::DW_AT_data_member_location;
    type Target = u64;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        value.udata_value()
    }
}

struct DwAtEncoding;
impl DwarfAttribute for DwAtEncoding {
    const DW_AT: gimli::DwAt = gimli::DW_AT_encoding;
    type Target = gimli::DwAte;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        match value {
            gimli::AttributeValue::Encoding(ate) => Some(ate),
            _ => None,
        }
    }
}

struct DwAtDeclaration;
impl DwarfAttribute for DwAtDeclaration {
    const DW_AT: gimli::DwAt = gimli::DW_AT_declaration;
    type Target = bool;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        match value {
            gimli::AttributeValue::Flag(flag) => Some(flag),
            _ => None,
        }
    }
}

/// A DWARF node has an entry and children
struct DwarfNode<'a, 'u, 't, R: GimliReader>(gimli::EntriesTreeNode<'a, 'u, 't, R>);

impl<'a, 'u, 't, R: GimliReader> DwarfNode<'a, 'u, 't, R> {
    fn entry<'me>(&'me self) -> DwarfEntry<'me, 'a, 'u, R> {
        DwarfEntry(self.0.entry())
    }

    /// Reads the node as a struct
    fn read_struct(self, debug_str: &DebugStr<R>) -> ResolveTypeResult<Option<LazyStruct>> {
        let entry = self.entry();

        // Ignore anonymous types
        if entry.try_read::<DwAtDeclaration>()? == Some(true) {
            return Ok(None);
        }

        // Zero-sized types may not have their size declared
        let size = entry.try_read::<DwAtByteSize>()?.unwrap_or(0);

        // Collect fields
        let mut fields = Vec::new();

        let mut children = self.0.children();
        while let Some(node) = children.next()? {
            let node = DwarfNode(node);
            fields.push(node.entry().read_struct_member(debug_str)?);
        }

        Ok(Some(LazyStruct {
            size,
            fields: fields.into(),
        }))
    }

    /// Reads the node as an union
    fn read_union(self, debug_str: &DebugStr<R>) -> ResolveTypeResult<LazyStruct> {
        let entry = self.entry();

        // Zero-sized types may not have their size declared
        let size = entry.try_read::<DwAtByteSize>()?.unwrap_or(0);

        // Collect fields
        let mut fields = Vec::new();

        let mut children = self.0.children();
        while let Some(node) = children.next()? {
            let node = DwarfNode(node);
            let (name, ty) = node.entry().read_union_member(debug_str)?;
            fields.push((0, name, ty));
        }

        Ok(LazyStruct {
            size,
            fields: fields.into(),
        })
    }

    fn read_type(
        self,
        debug_str: &DebugStr<R>,
    ) -> ResolveTypeResult<Option<(Option<String>, LazyType)>> {
        let entry = self.entry();
        let name = entry.try_read_name(debug_str)?;

        let typ = match entry.0.tag() {
            gimli::DW_TAG_typedef => {
                let offset = entry.read::<DwAtType>()?;
                return Ok(Some((name, LazyType::unresolved(offset))));
            }
            gimli::DW_TAG_base_type => DwarfType::Base(entry.read_base_type()?),
            gimli::DW_TAG_pointer_type => {
                let offset = entry.try_read::<DwAtType>()?;
                let typ = offset.map(|o| Rc::new(LazyType::unresolved(o)));
                DwarfType::Ptr(typ)
            }
            gimli::DW_TAG_structure_type => match self.read_struct(debug_str)? {
                Some(struct_) => DwarfType::Struct(struct_),
                None => return Ok(None),
            },
            gimli::DW_TAG_union_type => DwarfType::Union(self.read_union(debug_str)?),
            _ => return Ok(None),
        };

        Ok(Some((name, LazyType::resolved(typ))))
    }
}

struct DwarfEntry<'node, 'a, 'u, R: GimliReader>(
    &'node gimli::DebuggingInformationEntry<'a, 'u, R>,
);

impl<'node, 'a, 'u, R: GimliReader> Clone for DwarfEntry<'node, 'a, 'u, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'node, 'a, 'u, R: GimliReader> Copy for DwarfEntry<'node, 'a, 'u, R> {}

impl<'node, 'a, 'u, R: GimliReader> DwarfEntry<'node, 'a, 'u, R> {
    fn read_attr(self, name: gimli::DwAt) -> ResolveTypeResult<gimli::AttributeValue<R>> {
        self.0
            .attr_value(name)?
            .ok_or(ResolveTypeError::MissingAttr(name))
    }

    fn try_read_attr(
        self,
        name: gimli::DwAt,
    ) -> ResolveTypeResult<Option<gimli::AttributeValue<R>>> {
        Ok(self.0.attr_value(name)?)
    }

    /// Reads an attribute of the entry according to the type paramater
    ///
    /// Returns an error if the type is missing
    fn read<A: DwarfAttribute>(self) -> ResolveTypeResult<A::Target> {
        let value = self.read_attr(A::DW_AT)?;
        A::convert(value).ok_or(ResolveTypeError::WrongAttrType)
    }

    /// Reads an attribute of the entry according to the type paramater
    ///
    /// Returns an `Ok(None)` if the type is missing
    fn try_read<A: DwarfAttribute>(self) -> ResolveTypeResult<Option<A::Target>> {
        match self.try_read_attr(A::DW_AT)? {
            Some(value) => match A::convert(value) {
                Some(value) => Ok(Some(value)),
                None => Err(ResolveTypeError::WrongAttrType),
            },
            None => Ok(None),
        }
    }

    /// Reads the name attribute
    ///
    /// This is a separated method as it requires the DWARF string map
    fn try_read_name(self, debug_str: &gimli::DebugStr<R>) -> ResolveTypeResult<Option<String>> {
        Ok(match self.try_read_attr(gimli::DW_AT_name)? {
            Some(value) => {
                let name = value
                    .string_value(debug_str)
                    .ok_or(ResolveTypeError::WrongAttrType)?;
                Some(name.to_string()?.into_owned())
            }
            None => None,
        })
    }

    /// Reads a basic (integer) type
    fn read_base_type(self) -> ResolveTypeResult<BaseType> {
        let len = self.read::<DwAtByteSize>()?;
        let ate = self.read::<DwAtEncoding>()?;
        let signed = matches!(ate, gimli::DW_ATE_signed | gimli::DW_ATE_signed_char);

        Ok(BaseType { len, signed })
    }

    fn read_struct_member(
        self,
        debug_str: &gimli::DebugStr<R>,
    ) -> ResolveTypeResult<(u64, Option<String>, LazyType)> {
        let offset = self.read::<DwAtDataMemberLocation>()?;
        let name = self.try_read_name(debug_str)?;
        let typ = LazyType::unresolved(self.read::<DwAtType>()?);

        Ok((offset, name, typ))
    }

    fn read_union_member(
        self,
        debug_str: &gimli::DebugStr<R>,
    ) -> ResolveTypeResult<(Option<String>, LazyType)> {
        let name = self.try_read_name(debug_str)?;
        let typ = LazyType::unresolved(self.read::<DwAtType>()?);

        Ok((name, typ))
    }
}

#[derive(Debug, Clone, Copy)]
struct BaseType {
    len: u64,
    signed: bool,
}

/// A
#[derive(Debug, Clone)]
struct LazyStruct {
    size: u64,
    fields: Rc<[(u64, Option<String>, LazyType)]>,
}

#[derive(Debug, Clone)]
enum DwarfType {
    Base(BaseType),
    Ptr(Option<Rc<LazyType>>),
    Struct(LazyStruct),
    Union(LazyStruct),
}

impl DwarfType {
    fn is_fully_resolved(&self) -> bool {
        match self {
            DwarfType::Base(_) => true,
            DwarfType::Ptr(ty) => ty.as_ref().map_or(true, |ty| ty.is_resolved()),
            DwarfType::Struct(ty) | DwarfType::Union(ty) => {
                ty.fields.iter().all(|(_, _, ty)| ty.is_resolved())
            }
        }
    }
}

#[derive(Debug, Clone)]
enum LazyTypeInner {
    Unresolved(UnitOffset),
    Resolved(DwarfType),
}

impl Default for LazyTypeInner {
    fn default() -> Self {
        Self::Unresolved(UnitOffset(0))
    }
}

///  A DWARF type that is either resolved (we know its name, its fields, etc) or
/// not. In the latter case we only know its offset within the DWARF unit.
struct LazyType(Cell<LazyTypeInner>);

impl LazyType {
    const fn unresolved(offset: UnitOffset) -> Self {
        Self(Cell::new(LazyTypeInner::Unresolved(offset)))
    }

    fn resolved(typ: DwarfType) -> Self {
        Self(Cell::new(LazyTypeInner::Resolved(typ)))
    }

    fn with_inner<T>(&self, f: impl FnOnce(&LazyTypeInner) -> T) -> T {
        let old = self.0.take();
        let res = f(&old);
        self.0.set(old);
        res
    }

    fn with_inner_resolved<T>(&self, f: impl FnOnce(&DwarfType) -> T) -> Option<T> {
        self.with_inner(|inner| match inner {
            LazyTypeInner::Resolved(ty) => Some(f(ty)),
            LazyTypeInner::Unresolved(_) => None,
        })
    }

    fn with_inner_mut<T>(&self, f: impl FnOnce(&mut LazyTypeInner) -> T) -> T {
        let mut old = self.0.take();
        let res = f(&mut old);
        self.0.set(old);
        res
    }

    fn offset(&self) -> Option<UnitOffset> {
        self.with_inner(|ty| match ty {
            LazyTypeInner::Unresolved(offset) => Some(*offset),
            LazyTypeInner::Resolved(_) => None,
        })
    }

    fn is_resolved(&self) -> bool {
        self.with_inner(|ty| matches!(ty, LazyTypeInner::Resolved(_)))
    }

    fn into_resolved(self) -> Option<DwarfType> {
        match self.0.into_inner() {
            LazyTypeInner::Unresolved(_) => None,
            LazyTypeInner::Resolved(ty) => Some(ty),
        }
    }

    /// Try to resolve the current type or visit it
    fn resolve(
        &self,
        f: impl FnOnce(UnitOffset) -> Option<DwarfType>,
        g: impl FnOnce(&mut DwarfType),
    ) {
        let res = self.with_inner_mut(|ty| match ty {
            LazyTypeInner::Unresolved(offset) => Some(f(*offset)),
            LazyTypeInner::Resolved(ty) => {
                g(ty);
                None
            }
        });

        match res {
            Some(Some(ty)) => self.0.set(LazyTypeInner::Resolved(ty)),
            Some(None) => (),
            None => (),
        }
    }
}

impl Clone for LazyType {
    fn clone(&self) -> Self {
        let inner = self.with_inner(|inner| inner.clone());
        Self(Cell::new(inner))
    }
}

impl fmt::Debug for LazyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_inner(|l| l.fmt(f))
    }
}

#[derive(Debug)]
struct MidDataEntry {
    offset: UnitOffset,
    name: Option<String>,
    typ: LazyType,
}

struct MidData {
    types: Vec<MidDataEntry>,
    unresolved: VecDeque<usize>,
}

impl MidData {
    fn new() -> MidData {
        MidData {
            types: Vec::new(),
            unresolved: VecDeque::new(),
        }
    }

    fn find_by_offset(&self, offset: UnitOffset) -> Option<&MidDataEntry> {
        match self
            .types
            .binary_search_by_key(&offset, |entry| entry.offset)
        {
            Ok(index) => self.types.get(index),
            Err(_) => None,
        }
    }

    fn find_by_offset_mut(&mut self, offset: UnitOffset) -> Option<&mut MidDataEntry> {
        match self
            .types
            .binary_search_by_key(&offset, |entry| entry.offset)
        {
            Ok(index) => self.types.get_mut(index),
            Err(_) => None,
        }
    }
}

/// Fills `symbols` with types found in the given DWARF unit
fn fill<R: GimliReader>(
    unit: &gimli::UnitHeader<R>,
    abbrs: &gimli::Abbreviations,
    debug_str: &gimli::DebugStr<R>,
    symbols: &mut ibc::ModuleSymbols,
) -> gimli::Result<()> {
    // First pass: iterate all DWARF entries and store all types
    let mut types = Vec::new();

    let mut tree = unit.entries_tree(abbrs, None)?;
    let root = tree.root()?;
    let mut entries = root.children();

    while let Some(node) = entries.next()? {
        let node = DwarfNode(node);
        let entry = node.entry();

        let offset = entry.0.offset();

        match node.read_type(debug_str) {
            Ok(Some((name, typ))) => {
                types.push(MidDataEntry { offset, name, typ });
            }
            Ok(None) => (),
            Err(ResolveTypeError::Gimli(err)) => return Err(err),
            Err(err) => log::warn!("Failed to read DWARF entry: {}", err),
        }
    }

    /*
    TODO: Resolve types ?
    let mut types = MidData {
        unresolved: (0..types.len()).collect(),
        types,
    };

    while let Some(index) = types.unresolved.pop_front() {

    }
    */

    // Flatten anonymous types , eg:
    //
    // struct int_or_float {
    //     int kind;
    //     union { int x; float f; };
    // };
    for entry in &types {
        entry.typ.resolve(
            |_| None,
            |typ| {
                if let DwarfType::Struct(LazyStruct { fields, .. }) = typ {
                    // Quick case: there is no anynomous field
                    if fields.iter().all(|(_, name, _)| name.is_some()) {
                        return;
                    }

                    // Let's build a new field list
                    let mut new_fields = Vec::with_capacity(fields.len());
                    for (offset, name, ty) in fields.iter() {
                        match name {
                            // Named fields are easy
                            Some(_) => new_fields.push((*offset, name.clone(), ty.clone())),
                            None => {
                                // First, resolve inner types. This is necessary
                                // because types are lazily constructed
                                ty.resolve(
                                    |unit_offset| {
                                        let index = types
                                            .binary_search_by_key(&unit_offset, |entry| {
                                                entry.offset
                                            })
                                            .ok()?;
                                        let inner_typ = types.get(index)?;
                                        inner_typ.typ.clone().into_resolved()
                                    },
                                    |_| (),
                                );
                                // Then add the (hopefully) resolved type to our list of fields
                                ty.with_inner(|inner| match inner {
                                    LazyTypeInner::Unresolved(_) => {
                                        log::warn!(
                                            "Could not resolve anonymous field of struct {}",
                                            entry.name.as_deref().unwrap_or("<anonymous>")
                                        );
                                    }
                                    LazyTypeInner::Resolved(ty) => match ty {
                                        DwarfType::Struct(LazyStruct { fields, .. }) => new_fields
                                            .extend(fields.iter().map(|(o, name, ty)| {
                                                (offset + o, name.clone(), ty.clone())
                                            })),
                                        DwarfType::Union(_) => (), // TODO
                                        _ => {
                                            log::warn!("Anymous field is not a struct nor an union")
                                        }
                                    },
                                });
                            }
                        }
                    }

                    *fields = new_fields.into();
                }
            },
        );
    }

    // Finally we can add resolved types to debug infos
    symbols.extend(
        types
            .into_iter()
            .filter_map(|typ| typ.name.zip(typ.typ.into_resolved()))
            .filter_map(|(name, ty)| match ty {
                DwarfType::Struct(LazyStruct { size, fields }) => Some(ibc::symbols::OwnedStruct {
                    size,
                    name,
                    fields: fields
                        .iter()
                        .filter_map(|&(offset, ref name, _)| {
                            name.as_ref().map(|name| ibc::symbols::StructField {
                                name: name.clone(),
                                offset,
                            })
                        })
                        .collect(),
                }),
                _ => None,
            }),
    );

    Ok(())
}

/// Find an object's debug infos and load types to `symbols`
pub fn load_types(
    obj: &object::File,
    symbols: &mut ibc::ModuleSymbols,
) -> Result<(), relocations::Error> {
    let dwarf = relocations::load_dwarf(obj)?;
    Ok(load_types_from_dwarf(&dwarf, symbols)?)
}

/// Add types found in the DWARF to `symbols`
pub fn load_types_from_dwarf<R>(
    dwarf: &gimli::Dwarf<R>,
    symbols: &mut ibc::ModuleSymbols,
) -> Result<(), gimli::Error>
where
    R: gimli::Reader<Offset = usize>,
{
    let mut units = dwarf.units();
    while let Some(unit) = units.next()? {
        let abbrs = unit.abbreviations(&dwarf.debug_abbrev)?;
        fill(&unit, &abbrs, &dwarf.debug_str, symbols)?;
    }

    Ok(())
}
