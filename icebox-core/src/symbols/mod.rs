pub mod dwarf;
#[cfg(feature = "std")]
pub mod pdb;

use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt;
use hashbrown::HashMap;

use crate::{IceError, IceResult};

use super::VirtualAddress;

/// Demangles a symbol to a string.
///
/// If the symbol was not mangled or if the mangling scheme is unknown, the
/// symbol is returned as-is.
pub fn demangle(sym: &str) -> Cow<str> {
    if let Ok(sym) = rustc_demangle::try_demangle(sym) {
        return Cow::Owned(sym.to_string());
    }

    // TODO: Always enable cpp_demangle once it works with no_std
    #[cfg(feature = "std")]
    if let Ok(sym) = cpp_demangle::Symbol::new(sym) {
        return Cow::Owned(sym.to_string());
    }

    Cow::Borrowed(sym)
}

/// Demangles a symbol to a writer.
///
/// If the symbol was not mangled or if the mangling scheme is unknown, the
/// symbol is written as-is.
pub fn demangle_to<W: fmt::Write>(sym: &str, mut writer: W) -> fmt::Result {
    // TODO: Always enable cpp_demangle once it works with no_std
    #[cfg(feature = "std")]
    if let Ok(sym) = cpp_demangle::Symbol::new(sym) {
        writer.write_fmt(format_args!("{sym}"))?;
        return Ok(());
    }

    if let Ok(sym) = rustc_demangle::try_demangle(sym) {
        writer.write_fmt(format_args!("{sym}"))?;
        return Ok(());
    }

    writer.write_str(sym)
}

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

    types: HashMap<String, OwnedStruct>,
}

impl ModuleSymbols {
    fn new() -> Self {
        Self {
            names: HashMap::new(),
            addresses: HashMap::new(),
            types: HashMap::new(),
        }
    }

    pub fn get_symbols(&self, addr: VirtualAddress) -> Option<&str> {
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

    pub fn iter_symbols(&self) -> impl ExactSizeIterator<Item = (VirtualAddress, &str)> {
        self.names.iter().map(|(&addr, name)| (addr, &**name))
    }

    pub fn get_struct(&self, name: &str) -> IceResult<Struct> {
        match self.types.get(name) {
            Some(s) => Ok(s.borrow()),
            None => Err(IceError::missing_symbol(name)),
        }
    }

    pub fn insert_struct(&mut self, structure: OwnedStruct) {
        self.types.insert(structure.name.clone(), structure);
    }

    #[cfg(feature = "std")]
    #[inline]
    pub fn read_object_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> IceResult<()> {
        let content = std::fs::read(path)?;
        self.read_object_from_bytes(&content)
    }

    pub fn read_object_from_bytes(&mut self, obj: &[u8]) -> IceResult<()> {
        let obj = object::File::parse(obj).map_err(IceError::new)?;
        crate::symbols::dwarf::load_types(&obj, self).map_err(IceError::new)
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

impl Extend<OwnedStruct> for ModuleSymbols {
    fn extend<I: IntoIterator<Item = OwnedStruct>>(&mut self, iter: I) {
        self.types
            .extend(iter.into_iter().map(|s| (s.name.clone(), s)))
    }
}

impl fmt::Debug for ModuleSymbols {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter_symbols()).finish()
    }
}

#[derive(Debug, Default)]
pub struct SymbolsIndexer {
    modules: HashMap<Box<str>, ModuleSymbols>,
}

impl SymbolsIndexer {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub fn get_addr(&self, lib: &str, name: &str) -> IceResult<VirtualAddress> {
        self.get_lib(lib)?.get_address(name)
    }

    pub fn insert_addr(&mut self, lib: Box<str>, symbol: &str, addr: VirtualAddress) {
        self.get_lib_mut(lib).push(addr, symbol);
    }

    pub fn get_lib(&self, name: &str) -> IceResult<&ModuleSymbols> {
        match self.modules.get(name) {
            Some(lib) => Ok(lib),
            None => Err(IceError::missing_module(name)),
        }
    }

    pub fn get_lib_mut(&mut self, name: Box<str>) -> &mut ModuleSymbols {
        self.modules.entry(name).or_insert_with(ModuleSymbols::new)
    }
}
