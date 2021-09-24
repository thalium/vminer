use std::{borrow::Cow, collections::HashMap, fmt, fs, rc::Rc};

use fallible_iterator::FallibleIterator;
use object::{Object, ObjectSection, ObjectSymbol};

fn main() {
    let file = std::env::args_os().nth(1).expect("file name");
    let content = fs::read(&file).unwrap();
    let obj = object::File::parse(&*content).unwrap();

    parse_dwarf(&obj).unwrap();
}

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
                _ => {}
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
                match relocation.target() {
                    object::RelocationTarget::Symbol(symbol_idx) => {
                        match file.symbol_by_index(symbol_idx) {
                            Ok(symbol) => {
                                let addend =
                                    symbol.address().wrapping_add(relocation.addend() as u64);
                                relocation.set_addend(addend as i64);
                            }
                            Err(_) => {
                                eprintln!(
                                    "Relocation with invalid symbol for section {} at offset 0x{:08x}",
                                    section.name().unwrap(),
                                    offset
                                );
                            }
                        }
                    }
                    _ => {}
                }
                if relocations.insert(offset, relocation).is_some() {
                    eprintln!(
                        "Multiple relocations for section {} at offset 0x{:08x}",
                        section.name().unwrap(),
                        offset
                    );
                }
            }
            _ => {
                eprintln!(
                    "Unsupported relocation for section {} at offset 0x{:08x}",
                    section.name().unwrap(),
                    offset
                );
            }
        }
    }
}

fn load_file_section<'input, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
) -> object::Result<Relocate<gimli::EndianSlice<'input, Endian>>> {
    let mut relocations = RelocationMap::new();
    let name = id.name();

    let data = match file.section_by_name(&name) {
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
    let relocations = Rc::new(relocations);
    Ok(Relocate {
        relocations,
        section,
        reader,
    })
}

#[derive(Debug)]
pub enum Error {
    GimliError(gimli::Error),
    ObjectError(object::Error),
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        match self {
            Error::GimliError(_) => f.write_str("failed to read DWARF data"),
            Error::ObjectError(_) => f.write_str("failed to read ELF"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Error::GimliError(err) => err,
            Error::ObjectError(err) => err,
        })
    }
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::GimliError(err)
    }
}

impl From<object::Error> for Error {
    fn from(err: object::Error) -> Self {
        Error::ObjectError(err)
    }
}

fn parse_entry<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    debug_str: &gimli::DebugStr<R>,
    level: usize,
) -> gimli::Result<()>
where
    R::Offset: fmt::LowerHex,
{
    println!(
        "{:width$}{}: {:?}",
        "",
        entry.tag().static_string().unwrap(),
        entry.offset(),
        width = level * 2,
    );
    entry.attrs().for_each(|attr| {
        let name = attr.name().static_string().unwrap();
        let value = match attr.string_value(debug_str) {
            Some(value) => value.to_string_lossy()?.to_string(),
            None => format!("{:?}", attr.value()),
        };
        println!("{:width$}{}: {}", "", name, value, width = 2 * (level + 2));
        Ok(())
    })?;
    Ok(())
}

fn traverse_tree<R: gimli::Reader>(
    node: gimli::EntriesTreeNode<R>,
    debug_str: &gimli::DebugStr<R>,
    level: usize,
) -> gimli::Result<()>
where
    R::Offset: fmt::LowerHex,
{
    parse_entry(node.entry(), debug_str, level)?;

    let mut children = node.children();
    while let Some(child) = children.next()? {
        traverse_tree(child, debug_str, level + 1)?;
    }
    Ok(())
}

fn parse_dwarf(obj: &object::File) -> Result<(), Error> {
    let endian = match obj.is_little_endian() {
        true => gimli::RunTimeEndian::Little,
        false => gimli::RunTimeEndian::Big,
    };

    let dwarf = gimli::Dwarf::load(|section| load_file_section(section, obj, endian))?;

    dwarf.units().for_each(|unit| {
        println!("\n=== Parsing unit ===");
        println!("offset: {:?}\ntype: {:?}\n", unit.offset(), unit.version());
        let abbrs = unit.abbreviations(&dwarf.debug_abbrev)?;
        let mut tree = unit.entries_tree(&abbrs, None)?;
        traverse_tree(tree.root()?, &dwarf.debug_str, 0)?;
        Ok(())
    })?;

    Ok(())
}
