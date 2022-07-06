pub mod dwarf;
#[cfg(feature = "std")]
pub mod pdb;
pub mod symbols_file;

use super::VirtualAddress;
use crate::{IceError, IceResult, ResultExt};
use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{fmt, ops::Range};
use hashbrown::HashMap;
#[cfg(not(feature = "std"))]
use once_map::unsync::OnceMap;
#[cfg(feature = "std")]
use once_map::OnceMap;
#[cfg(feature = "std")]
use std::{fs, path};

/// Demangles a symbol to a string.
///
/// If the symbol was not mangled or if the mangling scheme is unknown, the
/// symbol is returned as-is.
pub fn demangle(sym: &str) -> Cow<str> {
    if let Ok(sym) = rustc_demangle::try_demangle(sym) {
        return Cow::Owned(sym.to_string());
    }

    // TODO: Always enable these once they work with no_std
    #[cfg(feature = "std")]
    if let Ok(sym) = cpp_demangle::Symbol::new(sym) {
        return Cow::Owned(sym.to_string());
    }

    #[cfg(feature = "std")]
    if let Ok(sym) = msvc_demangler::demangle(sym, msvc_demangler::DemangleFlags::NAME_ONLY) {
        return Cow::Owned(sym);
    }

    Cow::Borrowed(sym)
}

/// Demangles a symbol to a writer.
///
/// If the symbol was not mangled or if the mangling scheme is unknown, the
/// symbol is written as-is.
pub fn demangle_to<W: fmt::Write>(sym: &str, mut writer: W) -> fmt::Result {
    if let Ok(sym) = rustc_demangle::try_demangle(sym) {
        writer.write_fmt(format_args!("{sym}"))?;
        return Ok(());
    }

    // TODO: Always enable these once they work with no_std
    #[cfg(feature = "std")]
    if let Ok(sym) = cpp_demangle::Symbol::new(sym) {
        writer.write_fmt(format_args!("{sym}"))?;
        return Ok(());
    }

    #[cfg(feature = "std")]
    if let Ok(sym) = msvc_demangler::demangle(sym, msvc_demangler::DemangleFlags::NAME_ONLY) {
        writer.write_str(&sym)?;
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

#[derive(Debug, Default)]
pub struct ModuleSymbolsBuilder {
    buffer: String,
    symbols: Vec<(VirtualAddress, Range<usize>)>,
    types: HashMap<String, OwnedStruct>,
}

impl ModuleSymbolsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> ModuleSymbols {
        let buffer = self.buffer.into_boxed_str();

        let mut names = self.symbols.into_boxed_slice();
        names.sort_unstable_by_key(|(addr, _)| *addr);

        let mut addresses = names.clone();
        addresses.sort_unstable_by_key(|(_, range)| &buffer[range.clone()]);

        ModuleSymbols {
            buffer,
            symbols: names,
            addresses,
            types: self.types,
        }
    }

    pub fn push(&mut self, addr: VirtualAddress, symbol: &str) {
        let start = self.buffer.len();
        self.buffer.push_str(symbol);
        let end = self.buffer.len();
        self.symbols.push((addr, start..end))
    }

    pub fn insert_struct(&mut self, structure: OwnedStruct) {
        self.types.insert(structure.name.clone(), structure);
    }

    #[cfg(feature = "std")]
    pub fn read_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> IceResult<()> {
        self.read_file_inner(path.as_ref())
    }

    #[cfg(feature = "std")]
    fn read_file_inner(&mut self, path: &std::path::Path) -> IceResult<()> {
        let content = std::fs::read(path)?;
        self.read_bytes(&content)
    }

    pub fn read_bytes(&mut self, content: &[u8]) -> IceResult<()> {
        if content.starts_with(b"\x7fELF") {
            let obj = object::File::parse(content).map_err(IceError::new)?;
            crate::symbols::dwarf::load_types(&obj, self).map_err(IceError::new)?;
            return Ok(());
        }

        #[cfg(feature = "std")]
        if content.starts_with(b"Microsoft C/C++") {
            let content = std::io::Cursor::new(content);
            let mut pdb = ::pdb::PDB::open(content).map_err(IceError::new)?;
            pdb::load_syms(&mut pdb, self).map_err(IceError::new)?;
            pdb::load_types(&mut pdb, self).map_err(IceError::new)?;

            return Ok(());
        }

        symbols_file::read_from_bytes(content, self)
    }
}

impl<S: AsRef<str>> Extend<(VirtualAddress, S)> for ModuleSymbolsBuilder {
    fn extend<I: IntoIterator<Item = (VirtualAddress, S)>>(&mut self, iter: I) {
        self.symbols.extend(iter.into_iter().map(|(addr, sym)| {
            let start = self.buffer.len();
            self.buffer.push_str(sym.as_ref());
            let end = self.buffer.len();
            (addr, (start..end))
        }))
    }
}

impl Extend<OwnedStruct> for ModuleSymbolsBuilder {
    fn extend<I: IntoIterator<Item = OwnedStruct>>(&mut self, iter: I) {
        self.types
            .extend(iter.into_iter().map(|s| (s.name.clone(), s)))
    }
}

#[derive(Default)]
pub struct ModuleSymbols {
    buffer: Box<str>,

    /// Sorted by address to find names
    symbols: Box<[(VirtualAddress, Range<usize>)]>,

    /// Sorted by name to find addresses
    addresses: Box<[(VirtualAddress, Range<usize>)]>,

    types: HashMap<String, OwnedStruct>,
}

impl ModuleSymbols {
    #[cfg(feature = "std")]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> IceResult<Self> {
        let mut module = ModuleSymbolsBuilder::new();
        module.read_file_inner(path.as_ref())?;
        Ok(module.build())
    }

    pub fn from_bytes(content: &[u8]) -> IceResult<Self> {
        let mut module = ModuleSymbolsBuilder::new();
        module.read_bytes(content)?;
        Ok(module.build())
    }

    fn symbol(&self, range: Range<usize>) -> &str {
        &self.buffer[range]
    }

    pub fn get_symbol(&self, addr: VirtualAddress) -> Option<&str> {
        let index = self.symbols.binary_search_by_key(&addr, |(a, _)| *a).ok()?;
        Some(self.symbol(self.symbols[index].1.clone()))
    }

    pub fn get_symbol_inexact(&self, addr: VirtualAddress) -> Option<(&str, u64)> {
        let (range, offset) = match self.symbols.binary_search_by_key(&addr, |(a, _)| *a) {
            Ok(i) => (&self.symbols[i].1, 0),
            Err(i) => {
                let i = i.checked_sub(1)?;
                let (sym_addr, range) = &self.symbols[i];
                (range, (addr - *sym_addr) as u64)
            }
        };
        Some((self.symbol(range.clone()), offset))
    }

    pub fn get_address(&self, name: &str) -> IceResult<VirtualAddress> {
        let index = self
            .addresses
            .binary_search_by_key(&name, |(_, range)| self.symbol(range.clone()))
            .map_err(|_| IceError::missing_symbol(name))?;
        Ok(self.addresses[index].0)
    }

    pub fn iter_symbols(&self) -> impl ExactSizeIterator<Item = (VirtualAddress, &str)> {
        self.symbols
            .iter()
            .map(|(addr, range)| (*addr, self.symbol(range.clone())))
    }

    pub fn get_struct(&self, name: &str) -> IceResult<Struct> {
        match self.types.get(name) {
            Some(s) => Ok(s.borrow()),
            None => Err(IceError::missing_symbol(name)),
        }
    }
}

impl fmt::Debug for ModuleSymbols {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter_symbols()).finish()
    }
}

#[derive(Debug, Default)]
pub struct SymbolsIndexer {
    modules: OnceMap<Box<str>, Arc<Option<ModuleSymbols>>>,
}

impl SymbolsIndexer {
    pub fn new() -> Self {
        Self {
            modules: OnceMap::new(),
        }
    }

    pub fn get_addr(&self, lib: &str, name: &str) -> IceResult<VirtualAddress> {
        self.require_module(lib)?.get_address(name)
    }

    pub fn get_module(&self, name: &str) -> Option<&ModuleSymbols> {
        self.modules.get(name)?.as_ref()
    }

    pub fn require_module(&self, name: &str) -> IceResult<&ModuleSymbols> {
        self.get_module(name)
            .ok_or_else(|| IceError::missing_module(name))
    }

    pub fn load_module(
        &self,
        name: Box<str>,
        f: &mut dyn FnMut(&str) -> IceResult<Arc<Option<ModuleSymbols>>>,
    ) -> IceResult<Option<&ModuleSymbols>> {
        let module = self.modules.try_insert(name, |name| {
            f(name).with_context(|| alloc::format!("failed to load symbols for module \"{name}\""))
        })?;
        Ok(module.as_ref())
    }

    pub fn load_from_bytes(
        &mut self,
        name: Box<str>,
        content: &[u8],
    ) -> IceResult<Option<&ModuleSymbols>> {
        self.load_module(name, &mut |_| {
            ModuleSymbols::from_bytes(content).map(Some).map(Arc::new)
        })
    }

    #[cfg(feature = "std")]
    #[inline]
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
    ) -> IceResult<Option<&ModuleSymbols>> {
        self.load_from_file_inner(path.as_ref())
    }

    #[cfg(feature = "std")]
    fn load_from_file_inner(
        &mut self,
        path: &std::path::Path,
    ) -> IceResult<Option<&ModuleSymbols>> {
        let name = path
            .file_name()
            .context("no file name")?
            .to_str()
            .context("non UTF-8 file name")?
            .into();

        self.load_module(name, &mut |_| {
            ModuleSymbols::from_file(path).map(Some).map(Arc::new)
        })
    }

    #[cfg(feature = "std")]
    fn load_dir_inner(&mut self, path: &path::Path) -> IceResult<()> {
        for entry in fs::read_dir(path)? {
            match entry {
                Ok(entry) => {
                    let path = entry.path();
                    if let Err(err) = self.load_from_file_inner(&path) {
                        log::warn!("Error reading {}: {err}", path.display());
                    }
                }
                Err(err) => {
                    log::warn!("Failed to read directory entry: {err}")
                }
            };
        }

        Ok(())
    }

    /// Reads profile data from the given directory.
    #[cfg(feature = "std")]
    #[inline]
    pub fn load_dir<P: AsRef<path::Path>>(&mut self, path: P) -> IceResult<()> {
        self.load_dir_inner(path.as_ref())
    }
}
