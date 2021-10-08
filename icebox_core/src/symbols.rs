use alloc::{string::String, vec::Vec};
use hashbrown::HashMap;

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

#[derive(Debug)]
pub struct Struct<'a> {
    pub name: &'a str,
    pub fields: &'a [StructField],
}

pub struct SymbolsIndexer {
    structs: HashMap<String, OwnedStruct>,
}

impl SymbolsIndexer {
    pub fn new() -> Self {
        Self {
            structs: HashMap::new(),
        }
    }

    pub fn get_struct(&self, name: &str) -> Option<Struct> {
        self.structs.get(name).map(OwnedStruct::borrow)
    }

    pub fn insert_struct(&mut self, structure: OwnedStruct) {
        self.structs.insert(structure.name.clone(), structure);
    }
}

impl Extend<OwnedStruct> for SymbolsIndexer {
    fn extend<I: IntoIterator<Item = OwnedStruct>>(&mut self, iter: I) {
        self.structs
            .extend(iter.into_iter().map(|s| (s.name.clone(), s)))
    }
}
