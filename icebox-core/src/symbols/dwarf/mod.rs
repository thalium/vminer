#![allow(dead_code)]

use crate as ibc;
use alloc::{string::String, vec::Vec};
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
                "missing required attribute: {}",
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

struct DwAtDataBitOffset;
impl DwarfAttribute for DwAtDataBitOffset {
    const DW_AT: gimli::DwAt = gimli::DW_AT_data_bit_offset;
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

struct DwAtUpperBound;
impl DwarfAttribute for DwAtUpperBound {
    const DW_AT: gimli::DwAt = gimli::DW_AT_upper_bound;
    type Target = i64;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        value.sdata_value()
    }
}

struct DwAtCount;
impl DwarfAttribute for DwAtCount {
    const DW_AT: gimli::DwAt = gimli::DW_AT_count;
    type Target = u64;

    fn convert<R: GimliReader>(value: gimli::AttributeValue<R>) -> Option<Self::Target> {
        value.udata_value()
    }
}

/// A DWARF node has an entry and children
struct DwarfNode<'a, 'u, 't, R: GimliReader>(gimli::EntriesTreeNode<'a, 'u, 't, R>);

impl<'a, 'u, 't, R: GimliReader> DwarfNode<'a, 'u, 't, R> {
    fn entry<'me>(&'me self) -> DwarfEntry<'me, 'a, 'u, R> {
        DwarfEntry(self.0.entry())
    }

    /// Reads the node as a struct
    fn read_struct(self, debug_str: &DebugStr<R>) -> ResolveTypeResult<Option<DwarfStruct>> {
        let entry = self.entry();

        // This is a declaration only
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

        Ok(Some(DwarfStruct { size, fields }))
    }

    /// Reads the node as an union
    fn read_union(self, debug_str: &DebugStr<R>) -> ResolveTypeResult<DwarfStruct> {
        let entry = self.entry();

        // Zero-sized types may not have their size declared
        let size = entry.try_read::<DwAtByteSize>()?.unwrap_or(0);

        // Collect fields
        let mut fields = Vec::new();

        let mut children = self.0.children();
        while let Some(node) = children.next()? {
            let node = DwarfNode(node);
            let (name, ty) = node.entry().read_union_member(debug_str)?;
            fields.push((FieldOffset::Bytes(0), name, ty));
        }

        Ok(DwarfStruct { size, fields })
    }

    fn read_array(self) -> ResolveTypeResult<(UnitOffset, u32)> {
        let entry = self.entry();
        let typ = entry.read::<DwAtType>()?;

        let mut children = self.0.children();
        let mut dim = 1;

        while let Some(node) = children.next()? {
            let node = DwarfNode(node);

            let child_entry = node.entry();
            if child_entry.0.tag() != gimli::DW_TAG_subrange_type {
                return Err(ResolveTypeError::WrongAttrType);
            }

            let size = match child_entry.try_read::<DwAtUpperBound>()? {
                Some(bound) if bound < 0 => 0, // I don't known what this means
                Some(bound) => bound as u64 + 1,
                None => child_entry.try_read::<DwAtCount>()?.unwrap_or(0),
            };

            dim *= size as u32;
        }

        Ok((typ, dim))
    }

    fn read_type(
        self,
        debug_str: &DebugStr<R>,
    ) -> ResolveTypeResult<Option<(Option<String>, DwarfType)>> {
        let entry = self.entry();
        let name = entry.try_read_name(debug_str)?;

        let typ = match entry.0.tag() {
            gimli::DW_TAG_typedef => DwarfType::Typedef(entry.read::<DwAtType>()?),
            gimli::DW_TAG_base_type => DwarfType::Primitive(entry.read_base_type()?),
            gimli::DW_TAG_pointer_type => DwarfType::Ptr(entry.try_read::<DwAtType>()?),
            gimli::DW_TAG_structure_type => match self.read_struct(debug_str)? {
                Some(struct_) => DwarfType::Struct(struct_),
                None => DwarfType::StructDeclaration,
            },
            gimli::DW_TAG_union_type => DwarfType::Union(self.read_union(debug_str)?),
            gimli::DW_TAG_array_type => {
                let (typ, size) = self.read_array()?;
                DwarfType::Array(typ, size)
            }
            gimli::DW_TAG_subroutine_type => DwarfType::Function,
            gimli::DW_TAG_subprogram | gimli::DW_TAG_variable => return Ok(None),
            tag => {
                log::trace!("Unsupported tag: {tag}");
                return Ok(None);
            }
        };

        Ok(Some((name, typ)))
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

    /// Reads an attribute of the entry according to the type parameter
    ///
    /// Returns an error if the type is missing
    fn read<A: DwarfAttribute>(self) -> ResolveTypeResult<A::Target> {
        let value = self.read_attr(A::DW_AT)?;
        A::convert(value).ok_or(ResolveTypeError::WrongAttrType)
    }

    /// Reads an attribute of the entry according to the type parameter
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
    ) -> ResolveTypeResult<(FieldOffset, Option<String>, UnitOffset)> {
        // Bitfields use `DW_AT_data_bit_offset` instead of `DW_AT_data_member_location`
        let field_offset = match self.try_read::<DwAtDataMemberLocation>()? {
            Some(offset) => FieldOffset::Bytes(offset),
            None => FieldOffset::Bits(self.read::<DwAtDataBitOffset>()?),
        };

        let name = self.try_read_name(debug_str)?;
        let typ_offset = self.read::<DwAtType>()?;

        Ok((field_offset, name, typ_offset))
    }

    fn read_union_member(
        self,
        debug_str: &gimli::DebugStr<R>,
    ) -> ResolveTypeResult<(Option<String>, UnitOffset)> {
        let name = self.try_read_name(debug_str)?;
        let typ_offset = self.read::<DwAtType>()?;

        Ok((name, typ_offset))
    }
}

#[derive(Debug, Clone, Copy)]
struct BaseType {
    len: u64,
    signed: bool,
}

impl BaseType {
    fn to_primitive(self) -> super::Type {
        match (self.len, self.signed) {
            (1, true) => super::TypeKind::i8(),
            (1, false) => super::TypeKind::u8(),
            (2, true) => super::TypeKind::i16(),
            (2, false) => super::TypeKind::u16(),
            (4, true) => super::TypeKind::i32(),
            (4, false) => super::TypeKind::u32(),
            (8, true) => super::TypeKind::i64(),
            (8, false) => super::TypeKind::u64(),
            _ => super::TypeKind::unknown(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FieldOffset {
    Bytes(u64),
    Bits(u64),
}

#[derive(Debug)]
struct DwarfStruct {
    size: u64,
    fields: Vec<(FieldOffset, Option<String>, UnitOffset)>,
}

#[derive(Debug)]
enum DwarfType {
    Primitive(BaseType),
    Struct(DwarfStruct),
    StructDeclaration,
    Union(DwarfStruct),
    Ptr(Option<UnitOffset>),
    Typedef(UnitOffset),
    Array(UnitOffset, u32),
    Function,
}

struct TypeEntry {
    offset: UnitOffset,
    name: Option<String>,
    dwarf_type: DwarfType,
    typ: Cell<Option<super::Type>>,
}

struct TypeList {
    types: Vec<TypeEntry>,
}

impl TypeList {
    fn new() -> TypeList {
        TypeList { types: Vec::new() }
    }

    fn push(&mut self, entry: TypeEntry) {
        self.types.push(entry)
    }

    fn find_by_offset(&self, offset: UnitOffset) -> Option<&TypeEntry> {
        match self
            .types
            .binary_search_by_key(&offset, |entry| entry.offset)
        {
            Ok(index) => self.types.get(index),
            Err(_) => None,
        }
    }

    fn find_by_offset_mut(&mut self, offset: UnitOffset) -> Option<&mut TypeEntry> {
        match self
            .types
            .binary_search_by_key(&offset, |entry| entry.offset)
        {
            Ok(index) => self.types.get_mut(index),
            Err(_) => None,
        }
    }

    fn classify_type(&self, typ: &TypeEntry) -> Option<super::Type> {
        use alloc::sync::Arc;

        let name = typ.name.as_ref();

        Some(match typ.dwarf_type {
            DwarfType::Primitive(p) => p.to_primitive(),
            DwarfType::Struct(_) => Arc::new(super::TypeKind::Struct(name?.clone())),
            DwarfType::StructDeclaration => Arc::new(super::TypeKind::Struct(name?.clone())),
            DwarfType::Union(_) => Arc::new(super::TypeKind::Union(name?.clone())),
            DwarfType::Ptr(offset) => {
                let inner = match offset.and_then(|o| self.get_type(o)) {
                    Some(ty) => ty,
                    None => super::TypeKind::unknown(),
                };
                Arc::new(super::TypeKind::Pointer(inner))
            }
            DwarfType::Typedef(offset) => return self.get_type(offset),
            DwarfType::Array(offset, size) => {
                let inner = self.get_type(offset)?;
                Arc::new(super::TypeKind::Array(inner, size))
            }
            DwarfType::Function => Arc::new(super::TypeKind::Function),
        })
    }

    fn get_type(&self, offset: UnitOffset) -> Option<super::Type> {
        let typ = self.find_by_offset(offset)?;

        let ty = typ.typ.take().or_else(|| self.classify_type(typ))?;
        typ.typ.set(Some(ty.clone()));
        Some(ty)
    }
}

fn collect_fields_into(
    fields: &mut Vec<super::StructField>,
    base_offset: u64,
    types: &TypeList,
    s: &DwarfStruct,
) {
    fields.reserve(s.fields.len());

    for &(offset, ref name, typ_offset) in &s.fields {
        let offset = match offset {
            FieldOffset::Bytes(offset) => base_offset + offset,
            // We don't really support bitfields at the moment, ignore them
            FieldOffset::Bits(_) => continue,
        };

        match name {
            Some(name) => fields.push(super::StructField {
                name: name.clone(),
                offset,
                typ: types
                    .get_type(typ_offset)
                    .unwrap_or_else(super::TypeKind::unknown),
            }),
            None => match types.find_by_offset(typ_offset) {
                Some(ty) => match &ty.dwarf_type {
                    DwarfType::Struct(s) | DwarfType::Union(s) => {
                        collect_fields_into(fields, offset, types, s)
                    }
                    _ => log::warn!("Anonymous field is not a struct nor an union"),
                },

                None => log::trace!("Unknown anonymous field"),
            },
        }
    }
}

fn collect_fields(types: &TypeList, s: &DwarfStruct) -> Vec<super::StructField> {
    let mut fields = Vec::new();
    collect_fields_into(&mut fields, 0, types, s);
    fields
}

/// Fills `symbols` with types found in the given DWARF unit
fn fill<R: GimliReader>(
    unit: &gimli::UnitHeader<R>,
    abbrs: &gimli::Abbreviations,
    debug_str: &gimli::DebugStr<R>,
    symbols: &mut super::ModuleSymbolsBuilder,
) -> gimli::Result<()> {
    // First pass: iterate all DWARF entries and store all types
    let mut types = TypeList::new();

    let mut tree = unit.entries_tree(abbrs, None)?;
    let root = tree.root()?;
    let mut entries = root.children();

    while let Some(node) = entries.next()? {
        let node = DwarfNode(node);
        let entry = node.entry();

        let offset = entry.0.offset();

        match node.read_type(debug_str) {
            Ok(Some((name, dwarf_type))) => {
                types.push(TypeEntry {
                    offset,
                    name,
                    dwarf_type,
                    typ: Cell::new(None),
                });
            }
            Ok(None) => (),
            Err(ResolveTypeError::Gimli(err)) => return Err(err),
            Err(err) => log::warn!("Failed to read DWARF entry: {}", err),
        }
    }

    // Finally we can add resolved types to debug infos
    symbols.extend(types.types.iter().filter_map(|typ| {
        let name = typ.name.as_ref()?.clone();

        match &typ.dwarf_type {
            &DwarfType::Struct(ref s @ DwarfStruct { size, .. }) => {
                let fields = collect_fields(&types, s);
                Some(ibc::symbols::Struct { size, name, fields })
            }
            _ => None,
        }
    }));

    Ok(())
}

/// Find an object's debug infos and load types to `symbols`
pub fn load_types(
    obj: &object::File,
    symbols: &mut super::ModuleSymbolsBuilder,
) -> Result<(), relocations::Error> {
    let dwarf = relocations::load_dwarf(obj)?;
    Ok(load_types_from_dwarf(&dwarf, symbols)?)
}

/// Add types found in the DWARF to `symbols`
pub fn load_types_from_dwarf<R>(
    dwarf: &gimli::Dwarf<R>,
    symbols: &mut super::ModuleSymbolsBuilder,
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
