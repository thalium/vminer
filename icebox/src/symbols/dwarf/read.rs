extern crate alloc;

use alloc::{borrow::Cow, fmt, rc::Rc};

use hashbrown::HashMap;
use object::{Object, ObjectSection, ObjectSymbol};

type RelocationMap = HashMap<usize, object::Relocation>;

#[derive(Clone)]
struct Relocate<R> {
    relocations: Rc<HashMap<usize, object::Relocation>>,
    section: R,
    reader: R,
}

impl<R> fmt::Debug for Relocate<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relocate").finish_non_exhaustive()
    }
}

impl<R: gimli::Reader<Offset = usize>> Relocate<R> {
    fn relocate(&self, offset: usize, value: u64) -> u64 {
        if let Some(relocation) = self.relocations.get(&offset) {
            match relocation.kind() {
                object::RelocationKind::Absolute => {
                    if relocation.has_implicit_addend() {
                        // Use the explicit addend too, because it may have the symbol value.
                        return value.wrapping_add(relocation.addend() as u64);
                    } else {
                        return relocation.addend() as u64;
                    }
                }
                _ => log::debug!("Unsupported relocation kind in ELF"),
            }
        };
        value
    }
}

impl<R: gimli::Reader<Offset = usize>> gimli::Reader for Relocate<R> {
    type Endian = R::Endian;
    type Offset = R::Offset;

    fn read_address(&mut self, address_size: u8) -> gimli::Result<u64> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_address(address_size)?;
        Ok(self.relocate(offset, value))
    }

    fn read_length(&mut self, format: gimli::Format) -> gimli::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_length(format)?;
        <usize as gimli::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    fn read_offset(&mut self, format: gimli::Format) -> gimli::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_offset(format)?;
        <usize as gimli::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    fn read_sized_offset(&mut self, size: u8) -> gimli::Result<usize> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_sized_offset(size)?;
        <usize as gimli::ReaderOffset>::from_u64(self.relocate(offset, value as u64))
    }

    #[inline]
    fn split(&mut self, len: Self::Offset) -> gimli::Result<Self> {
        let mut other = self.clone();
        other.reader.truncate(len)?;
        self.reader.skip(len)?;
        Ok(other)
    }

    // All remaining methods simply delegate to `self.reader`.

    #[inline]
    fn endian(&self) -> Self::Endian {
        self.reader.endian()
    }

    #[inline]
    fn len(&self) -> Self::Offset {
        self.reader.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.reader.empty()
    }

    #[inline]
    fn truncate(&mut self, len: Self::Offset) -> gimli::Result<()> {
        self.reader.truncate(len)
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> Self::Offset {
        self.reader.offset_from(&base.reader)
    }

    #[inline]
    fn offset_id(&self) -> gimli::ReaderOffsetId {
        self.reader.offset_id()
    }

    #[inline]
    fn lookup_offset_id(&self, id: gimli::ReaderOffsetId) -> Option<Self::Offset> {
        self.reader.lookup_offset_id(id)
    }

    #[inline]
    fn find(&self, byte: u8) -> gimli::Result<Self::Offset> {
        self.reader.find(byte)
    }

    #[inline]
    fn skip(&mut self, len: Self::Offset) -> gimli::Result<()> {
        self.reader.skip(len)
    }

    #[inline]
    fn to_slice(&self) -> gimli::Result<Cow<[u8]>> {
        self.reader.to_slice()
    }

    #[inline]
    fn to_string(&self) -> gimli::Result<Cow<str>> {
        self.reader.to_string()
    }

    #[inline]
    fn to_string_lossy(&self) -> gimli::Result<Cow<str>> {
        self.reader.to_string_lossy()
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> gimli::Result<()> {
        self.reader.read_slice(buf)
    }
}

fn add_relocations(
    relocations: &mut RelocationMap,
    file: &object::File,
    section: &object::Section,
) {
    for (offset64, mut relocation) in section.relocations() {
        let offset = offset64 as usize;
        if offset as u64 != offset64 {
            continue;
        }
        let offset = offset as usize;
        match relocation.kind() {
            object::RelocationKind::Absolute => {
                if let object::RelocationTarget::Symbol(symbol_idx) = relocation.target() {
                    match file.symbol_by_index(symbol_idx) {
                        Ok(symbol) => {
                            let addend = symbol.address().wrapping_add(relocation.addend() as u64);
                            relocation.set_addend(addend as i64);
                        }
                        Err(_) => {
                            log::warn!(
                                "Relocation with invalid symbol for section {} at offset 0x{:08x}",
                                section.name().unwrap_or("<unknown name>"),
                                offset
                            );
                        }
                    }
                }
                if relocations.insert(offset, relocation).is_some() {
                    log::warn!(
                        "Multiple relocations for section {} at offset 0x{:08x}",
                        section.name().unwrap_or("<unknown name>"),
                        offset
                    );
                }
            }
            _ => {
                log::warn!(
                    "Unsupported relocation for section {} at offset 0x{:08x}",
                    section.name().unwrap_or("<unknown name>"),
                    offset
                );
            }
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Gimli(gimli::Error),
    Object(object::Error),
    CompressedSection,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Error::Gimli(_) => f.write_str("failed to read DWARF data"),
            Error::Object(_) => f.write_str("failed to read ELF"),
            Error::CompressedSection => f.write_str("compressed DWARF sections are not supported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Error::Gimli(err) => err,
            Error::Object(err) => err,
            Error::CompressedSection => return None,
        })
    }
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::Gimli(err)
    }
}

impl From<object::Error> for Error {
    fn from(err: object::Error) -> Self {
        Error::Object(err)
    }
}

fn load_file_section<'input, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
) -> object::Result<Relocate<gimli::EndianSlice<'input, Endian>>> {
    let mut relocations = RelocationMap::new();
    let name = id.name();

    let data = match file.section_by_name(name) {
        Some(ref section) => {
            add_relocations(&mut relocations, file, section);
            match section.uncompressed_data()? {
                Cow::Borrowed(b) => b,
                Cow::Owned(_) => panic!("Unsupported compressed data"),
            }
        }
        None => &[],
    };
    let reader = gimli::EndianSlice::new(data, endian);
    let section = reader;
    Ok(Relocate {
        relocations: Rc::new(relocations),
        section,
        reader,
    })
}

pub fn load_dwarf<'a>(
    obj: &'a object::File,
) -> object::Result<gimli::Dwarf<impl gimli::Reader<Offset = usize> + 'a>> {
    let endian = match obj.is_little_endian() {
        true => gimli::RunTimeEndian::Little,
        false => gimli::RunTimeEndian::Big,
    };

    gimli::Dwarf::load(|section| load_file_section(section, obj, endian))
}
