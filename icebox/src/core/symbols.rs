use alloc::{string::String, vec::Vec};
use hashbrown::HashMap;

use super::GuestVirtAddr;

#[derive(Debug)]
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
            name: &self.name,
            fields: &self.fields,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Struct<'a> {
    pub name: &'a str,
    pub fields: &'a [StructField],
}

impl<'a> Struct<'a> {
    pub fn find_offset(&self, field_name: &str) -> Option<u64> {
        let field = self.fields.iter().find(|field| field.name == field_name)?;
        Some(field.offset)
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
