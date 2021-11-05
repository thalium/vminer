pub mod dwarf;

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use hashbrown::HashMap;

use super::GuestVirtAddr;

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub offset: u64,
}

#[derive(Debug)]
pub struct OwnedStruct {
    pub size: u64,
    pub name: String,
    pub fields: Vec<StructField>,
}

impl OwnedStruct {
    fn borrow(&self) -> Struct {
        Struct {
            size: self.size,
            name: &self.name,
            fields: &self.fields,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Struct<'a> {
    pub size: u64,
    pub name: &'a str,
    pub fields: &'a [StructField],
}

impl<'a> Struct<'a> {
    pub fn find_offset(&self, field_name: &str) -> Option<u64> {
        let field = self.fields.iter().find(|field| field.name == field_name)?;
        Some(field.offset)
    }

    pub fn find_offset_and_size(&self, field_name: &str) -> Option<(u64, u64)> {
        let (i, field) = self
            .fields
            .iter()
            .enumerate()
            .find(|(_, field)| field.name == field_name)?;
        let size = self.fields.get(i + 1).map_or(self.size, |f| f.offset) - field.offset;
        Some((field.offset, size))
    }

    pub fn into_owned(&self) -> OwnedStruct {
        OwnedStruct {
            size: self.size,
            name: self.name.to_owned(),
            fields: self.fields.to_owned(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SymbolsIndexer {
    structs: HashMap<String, OwnedStruct>,
    addresses: HashMap<String, GuestVirtAddr>,
}

impl SymbolsIndexer {
    pub fn new() -> Self {
        Self {
            structs: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    pub fn get_struct(&self, name: &str) -> Option<Struct> {
        self.structs.get(name).map(OwnedStruct::borrow)
    }

    pub fn insert_struct(&mut self, structure: OwnedStruct) {
        self.structs.insert(structure.name.clone(), structure);
    }

    pub fn get_addr(&self, name: &str) -> Option<GuestVirtAddr> {
        self.addresses.get(name).copied()
    }

    pub fn insert_addr(&mut self, name: String, addr: GuestVirtAddr) {
        self.addresses.insert(name, addr);
    }

    #[cfg(all(feature = "object", feature = "std"))]
    pub fn read_object_file<P: AsRef<std::path::Path>>(&mut self, path: P) {
        let content = std::fs::read(path).unwrap();
        let obj = object::File::parse(&*content).unwrap();
        self.read_object(&obj);
    }

    #[cfg(feature = "object")]
    pub fn read_object(&mut self, obj: &object::File) {
        crate::symbols::dwarf::load_types(obj, self).unwrap()
    }
}

impl Extend<OwnedStruct> for SymbolsIndexer {
    fn extend<I: IntoIterator<Item = OwnedStruct>>(&mut self, iter: I) {
        self.structs
            .extend(iter.into_iter().map(|s| (s.name.clone(), s)))
    }
}

impl Extend<(String, GuestVirtAddr)> for SymbolsIndexer {
    fn extend<I: IntoIterator<Item = (String, GuestVirtAddr)>>(&mut self, iter: I) {
        self.addresses.extend(iter)
    }
}
