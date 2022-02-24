pub mod dwarf;

use alloc::{borrow::ToOwned, boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;
use hashbrown::HashMap;

use crate::{IceError, IceResult};

use super::VirtualAddress;

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
    pub fn find_offset(&self, field_name: &str) -> IceResult<u64> {
        match self.fields.iter().find(|field| field.name == field_name) {
            Some(field) => Ok(field.offset),
            None => Err(IceError::missing_field(field_name, self.name)),
        }
    }

    pub fn find_offset_and_size(&self, field_name: &str) -> IceResult<(u64, u64)> {
        let (i, field) = self
            .fields
            .iter()
            .enumerate()
            .find(|(_, field)| field.name == field_name)
            .ok_or_else(|| IceError::missing_field(field_name, self.name))?;
        let size = self.fields.get(i + 1).map_or(self.size, |f| f.offset) - field.offset;
        Ok((field.offset, size))
    }

    pub fn into_owned(&self) -> OwnedStruct {
        OwnedStruct {
            size: self.size,
            name: self.name.to_owned(),
            fields: self.fields.to_owned(),
        }
    }
}

#[derive(Default)]
pub struct ModuleSymbols {
    // TODO: Try to store all string in a single buffer
    /// A map to translate addresses to names
    names: HashMap<VirtualAddress, Arc<str>>,

    /// A map to translate names to addresses
    addresses: HashMap<Arc<str>, VirtualAddress>,
}

impl ModuleSymbols {
    fn new() -> Self {
        Self {
            names: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    pub fn get_name(&self, addr: VirtualAddress) -> Option<&str> {
        Some(&**self.names.get(&addr)?)
    }

    pub fn get_address(&self, name: &str) -> IceResult<VirtualAddress> {
        match self.addresses.get(name) {
            Some(addr) => Ok(*addr),
            None => Err(IceError::missing_symbol(name)),
        }
    }

    pub fn push(&mut self, addr: VirtualAddress, symbol: &str) {
        let symbol = Arc::<str>::from(symbol);
        self.names.insert(addr, symbol.clone());
        self.addresses.insert(symbol, addr);
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (VirtualAddress, &str)> {
        self.names.iter().map(|(&addr, name)| (addr, &**name))
    }
}

impl<S: AsRef<str>> Extend<(VirtualAddress, S)> for ModuleSymbols {
    fn extend<I: IntoIterator<Item = (VirtualAddress, S)>>(&mut self, iter: I) {
        for (addr, symbol) in iter {
            self.push(addr, symbol.as_ref());
        }
    }
}

impl<S: AsRef<str>> Extend<(S, VirtualAddress)> for ModuleSymbols {
    fn extend<I: IntoIterator<Item = (S, VirtualAddress)>>(&mut self, iter: I) {
        for (symbol, addr) in iter {
            self.push(addr, symbol.as_ref());
        }
    }
}

impl fmt::Debug for ModuleSymbols {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[derive(Debug, Default)]
pub struct SymbolsIndexer {
    structs: HashMap<String, OwnedStruct>,
    symbols: HashMap<Box<str>, ModuleSymbols>,
}

impl SymbolsIndexer {
    pub fn new() -> Self {
        Self {
            structs: HashMap::new(),
            symbols: HashMap::new(),
        }
    }

    pub fn get_struct(&self, name: &str) -> IceResult<Struct> {
        match self.structs.get(name) {
            Some(s) => Ok(s.borrow()),
            None => Err(IceError::missing_symbol(name)),
        }
    }

    pub fn insert_struct(&mut self, structure: OwnedStruct) {
        self.structs.insert(structure.name.clone(), structure);
    }

    pub fn get_addr(&self, lib: &str, name: &str) -> IceResult<VirtualAddress> {
        self.get_lib(lib)?.get_address(name)
    }

    pub fn insert_addr(&mut self, lib: Box<str>, symbol: &str, addr: VirtualAddress) {
        self.get_lib_mut(lib).push(addr, symbol);
    }

    pub fn get_lib(&self, name: &str) -> IceResult<&ModuleSymbols> {
        match self.symbols.get(name) {
            Some(lib) => Ok(lib),
            None => Err(IceError::missing_module(name)),
        }
    }

    pub fn get_lib_mut(&mut self, name: Box<str>) -> &mut ModuleSymbols {
        self.symbols.entry(name).or_insert_with(ModuleSymbols::new)
    }

    #[cfg(all(feature = "object", feature = "std"))]
    fn _read_object_file(&mut self, path: &std::path::Path) -> IceResult<()> {
        let content = std::fs::read(path)?;
        (|| {
            let obj = object::File::parse(&*content)?;
            crate::symbols::dwarf::load_types(&obj, self)
        })()
        .map_err(IceError::new)
    }

    #[cfg(all(feature = "object", feature = "std"))]
    #[inline]
    pub fn read_object_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> IceResult<()> {
        self._read_object_file(path.as_ref())
    }

    #[cfg(feature = "object")]
    pub fn read_object(&mut self, obj: &object::File) -> IceResult<()> {
        crate::symbols::dwarf::load_types(obj, self).map_err(IceError::new)
    }
}

impl Extend<OwnedStruct> for SymbolsIndexer {
    fn extend<I: IntoIterator<Item = OwnedStruct>>(&mut self, iter: I) {
        self.structs
            .extend(iter.into_iter().map(|s| (s.name.clone(), s)))
    }
}
