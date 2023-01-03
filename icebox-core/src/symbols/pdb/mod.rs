use pdb::FallibleIterator;

struct TypeList<'t> {
    offset: usize,
    types: Vec<pdb::TypeData<'t>>,
}

impl<'t> TypeList<'t> {
    fn get(&self, index: pdb::TypeIndex) -> Option<&pdb::TypeData<'t>> {
        match self.types.get(index.0 as usize - self.offset) {
            Some(ty) => Some(ty),
            None => {
                log::warn!("Unable to resolve index {index:?}");
                None
            }
        }
    }
}

fn collect_fields(struct_name: &str, fields: &pdb::FieldList) -> Vec<crate::symbols::StructField> {
    fields
        .fields
        .iter()
        .filter_map(|item| match item {
            pdb::TypeData::Member(member) => {
                let name = core::str::from_utf8(member.name.as_bytes())
                    .ok()?
                    .to_owned();
                Some(crate::symbols::StructField {
                    name,
                    offset: member.offset,
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
            ty.parse()
        })
        .collect()?;

    let type_list = TypeList {
        offset: offset.unwrap_or(0x1000),
        types,
    };

    module.extend(type_list.types.iter().filter_map(|item| match item {
        pdb::TypeData::Class(ty) => {
            let name = core::str::from_utf8(ty.name.as_bytes()).ok()?.to_owned();

            let members = type_list.get(ty.fields?)?;

            if !matches!(ty.kind, pdb::ClassKind::Struct) {
                return None;
            }

            let fields = match members {
                pdb::TypeData::FieldList(fields) => collect_fields(&name, fields),
                _ => {
                    log::warn!("Struct \"{name}\" has weird field list: {members:?}");
                    return None;
                }
            };

            Some(crate::symbols::OwnedStruct {
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
