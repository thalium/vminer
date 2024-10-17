use super::{Type, TypeKind};
use alloc::sync::Arc;
use core::cell::Cell;
use pdb::FallibleIterator;

pub fn classify_primitive(ty: u32) -> Option<Type> {
    assert!(ty < 0x1000);

    Some(match ty {
        0x03 => TypeKind::void(),
        0x603 => TypeKind::void_ptr(),

        0x10 | 0x68 => TypeKind::i8(),
        0x610 | 0x668 => TypeKind::i8_ptr(),
        0x20 | 0x69 => TypeKind::u8(),
        0x620 | 0x669 => TypeKind::u8_ptr(),

        0x11 | 0x72 => TypeKind::i16(),
        0x611 | 0x672 => TypeKind::i16_ptr(),
        0x21 | 0x73 => TypeKind::u16(),
        0x621 | 0x673 => TypeKind::u16_ptr(),

        0x12 | 0x74 => TypeKind::i32(),
        0x612 | 0x674 => TypeKind::i32_ptr(),
        0x22 | 0x75 => TypeKind::u32(),
        0x622 | 0x675 => TypeKind::u32_ptr(),

        0x13 | 0x76 => TypeKind::i64(),
        0x613 | 0x676 => TypeKind::i64_ptr(),
        0x23 | 0x77 => TypeKind::u64(),
        0x623 | 0x677 => TypeKind::u64_ptr(),

        _ => return None,
    })
}

struct TypeList<'t> {
    offset: usize,
    types: Vec<(pdb::TypeData<'t>, Cell<Option<Type>>)>,
}

impl<'t> TypeList<'t> {
    fn get(&self, index: pdb::TypeIndex) -> Option<&pdb::TypeData<'t>> {
        match self.types.get(index.0 as usize - self.offset) {
            Some(ty) => Some(&ty.0),
            None => {
                log::warn!("Unable to resolve index {index:?}");
                None
            }
        }
    }

    fn classify_type(&self, typ: &pdb::TypeData) -> Option<Type> {
        let kind = match typ {
            pdb::TypeData::Array(a) => {
                let typ = self.get_type(a.element_type)?;
                if a.dimensions.len() != 1 {
                    println!("{a:?}");
                }
                let dim = a.dimensions.iter().product();
                TypeKind::Array(typ, dim)
            }
            pdb::TypeData::Bitfield(_) => TypeKind::Bitfield,
            pdb::TypeData::Class(c) => {
                let name = core::str::from_utf8(c.name.as_bytes()).ok()?.to_owned();
                TypeKind::Struct(name)
            }
            pdb::TypeData::Enumeration(e) => return self.get_type(e.underlying_type),
            pdb::TypeData::Modifier(m) => return self.get_type(m.underlying_type),
            pdb::TypeData::Procedure(_) => TypeKind::Function,
            pdb::TypeData::Pointer(p) => {
                let typ = self.get_type(p.underlying_type)?;
                TypeKind::Pointer(typ)
            }
            pdb::TypeData::Union(u) => {
                let name = core::str::from_utf8(u.name.as_bytes()).ok()?.to_owned();
                TypeKind::Union(name)
            }
            ty => {
                println!("Unsupported type: {ty:?}");
                return None;
            }
        };

        Some(Arc::new(kind))
    }

    fn get_type(&self, index: pdb::TypeIndex) -> Option<Type> {
        if index.0 < 0x1000 {
            return classify_primitive(index.0);
        }

        let (type_data, ty) = match self.types.get(index.0 as usize - self.offset) {
            Some(ty) => ty,
            None => {
                log::warn!("Unable to resolve index {index:?}");
                return None;
            }
        };

        if let Some(typ) = ty.take() {
            ty.set(Some(typ.clone()));
            return Some(typ);
        }

        let resolved_type = self.classify_type(type_data);

        ty.set(resolved_type.clone());
        resolved_type
    }
}

fn collect_fields(
    struct_name: &str,
    fields: &pdb::FieldList,
    list: &TypeList,
) -> Vec<crate::symbols::StructField> {
    fields
        .fields
        .iter()
        .filter_map(|item| match item {
            pdb::TypeData::Member(member) => {
                let typ = list
                    .get_type(member.field_type)
                    .unwrap_or_else(crate::symbols::TypeKind::unknown);

                let name = core::str::from_utf8(member.name.as_bytes())
                    .ok()?
                    .to_owned();
                Some(crate::symbols::StructField {
                    name,
                    offset: member.offset,
                    typ,
                })
            }
            _ => {
                log::debug!("Struct \"{struct_name}\" has unsupported field: {item:?}");
                None
            }
        })
        .collect()
}

pub fn load_types<'s, S: pdb::Source<'s> + 's>(
    pdb: &mut pdb::PDB<'s, S>,
    module: &mut super::ModuleSymbolsBuilder,
) -> Result<(), pdb::Error> {
    let types = pdb.type_information()?;

    let mut offset = None;

    // First, iterate all the type stream
    let types = types
        .iter()
        .enumerate()
        .map(|(i, ty)| {
            let index = ty.index().0 as usize;
            let offset = *offset.get_or_insert(index);
            assert_eq!(index, offset + i);
            let ty = ty.parse()?;

            Ok((ty, Cell::new(None)))
        })
        .collect()?;

    let type_list = TypeList {
        offset: offset.unwrap_or(0x1000),
        types,
    };

    module.extend(type_list.types.iter().filter_map(|(item, _)| match item {
        pdb::TypeData::Class(ty) => {
            let name = core::str::from_utf8(ty.name.as_bytes()).ok()?.to_owned();

            let members = type_list.get(ty.fields?)?;

            if !matches!(ty.kind, pdb::ClassKind::Struct) {
                return None;
            }

            let fields = match members {
                pdb::TypeData::FieldList(fields) => collect_fields(&name, fields, &type_list),
                _ => {
                    log::warn!("Struct \"{name}\" has weird field list: {members:?}");
                    return None;
                }
            };

            Some(crate::symbols::Struct {
                name,
                size: ty.size,
                fields,
            })
        }
        _ => None,
    }));

    Ok(())
}

pub fn load_syms<'s, S: pdb::Source<'s> + 's>(
    pdb: &mut pdb::PDB<'s, S>,
    module: &mut super::ModuleSymbolsBuilder,
) -> Result<(), pdb::Error> {
    let symbols = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;

    symbols.iter().for_each(|sym| match sym.parse()? {
        pdb::SymbolData::Public(sym) => {
            if let Some(addr) = sym.offset.to_rva(&address_map) {
                if let Ok(name) = std::str::from_utf8(sym.name.as_bytes()) {
                    let addr = crate::VirtualAddress(addr.0 as u64);
                    module.push(addr, name);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    })?;

    Ok(())
}
