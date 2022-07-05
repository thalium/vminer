use super::{MemoryAccessError, MemoryAccessResult, PhysicalAddress};
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::{fs, io, path::Path};

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
pub struct MemoryMap {
    pub start: PhysicalAddress,
    pub end: PhysicalAddress,
}

/// A trait to specify how to read physical memory from a guest
///
/// This trait defines additional optional methods for specialisation
pub trait Memory {
    fn mappings(&self) -> &[MemoryMap];

    #[inline]
    fn is_valid(&self, addr: PhysicalAddress, size: usize) -> bool {
        for mapping in self.mappings() {
            if mapping.start <= addr && addr + (size as u64) <= mapping.end {
                return true;
            }
        }

        false
    }

    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()>;

    /// Search in a memory page with a finder.
    ///
    /// A buffer is expected to avoid allocating a new one each time this
    /// function is called.
    ///
    /// Returns the index of the needle within the page if found.
    fn search(
        &self,
        addr: PhysicalAddress,
        page_size: u64,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> MemoryAccessResult<Option<u64>> {
        match buf.get_mut(..page_size as usize) {
            // Nice case, all the page fits in the buffer
            Some(buf) => {
                self.read(addr, buf)?;
                Ok(finder.find(buf).map(|i| i as u64))
            }
            // This is a bit more complicated, as we need several reads.
            None => {
                assert!(buf.len() > finder.needle().len());

                for offset in (0..page_size).step_by(buf.len() - finder.needle().len()) {
                    let addr = addr + offset;
                    let size = core::cmp::min(buf.len(), (page_size - offset) as usize);
                    self.read(addr, &mut buf[..size])?;
                    if let Some(index) = finder.find(&buf[..size]) {
                        return Ok(Some(index as u64));
                    }
                }

                Ok(None)
            }
        }
    }

    #[cfg(feature = "std")]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        let mut buffer = [0; 1 << 16];

        for mapping in self.mappings() {
            for addr in (mapping.start.0..mapping.end.0).step_by(buffer.len() as _) {
                self.read(PhysicalAddress(addr), &mut buffer)?;
                writer.write_all(&buffer)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct RawMemory<T: ?Sized> {
    mapping: MemoryMap,
    bytes: T,
}

impl<T: AsRef<[u8]>> RawMemory<T> {
    pub fn new(bytes: T) -> Self {
        Self {
            mapping: MemoryMap {
                start: PhysicalAddress(0),
                end: PhysicalAddress(bytes.as_ref().len() as u64),
            },
            bytes,
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Memory for RawMemory<T> {
    #[inline]
    fn mappings(&self) -> &[MemoryMap] {
        core::slice::from_ref(&self.mapping)
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (|| {
            let offset = addr.0.try_into().ok()?;
            let this = self.bytes.as_ref().get(offset..)?;
            let len = buf.len();
            (this.len() >= len).then(|| buf.copy_from_slice(&this[..len]))
        })()
        .ok_or(MemoryAccessError::OutOfBounds)
    }

    fn search(
        &self,
        addr: PhysicalAddress,
        page_size: u64,
        finder: &memchr::memmem::Finder,
        _buf: &mut [u8],
    ) -> MemoryAccessResult<Option<u64>> {
        let this = (|| {
            let max = addr.0.checked_add(page_size)?.try_into().ok()?;
            let offset = addr.0.try_into().ok()?;
            self.bytes.as_ref().get(offset..max)
        })()
        .ok_or(MemoryAccessError::OutOfBounds)?;

        Ok(finder.find(this).map(|i| i as u64))
    }

    #[cfg(feature = "std")]
    #[inline]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        writer.write_all(self.bytes.as_ref())
    }
}

#[derive(Debug)]
pub struct MemRemap<M: ?Sized> {
    mappings: Vec<MemoryMap>,
    remap_at: Vec<PhysicalAddress>,
    inner: M,
}

impl<M: Memory> MemRemap<M> {
    pub fn new(inner: M, mappings: Vec<MemoryMap>, remap_at: Vec<PhysicalAddress>) -> Self {
        Self {
            mappings,
            remap_at,
            inner,
        }
    }
}

impl<M: Memory + ?Sized> Memory for MemRemap<M> {
    fn mappings(&self) -> &[MemoryMap] {
        &self.mappings
    }

    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        assert!(self.mappings.len() == self.remap_at.len());

        let mut i = 0;
        let addr = loop {
            if i >= self.mappings.len() {
                return Err(MemoryAccessError::OutOfBounds);
            }

            let mapping = self.mappings[i];
            if mapping.start <= addr && addr + (buf.len() as u64) <= mapping.end {
                break self.remap_at[i] + (addr - mapping.start);
            }

            i += 1;
        };

        self.inner.read(addr, buf)
    }
}

impl<M: Memory + ?Sized> Memory for &'_ M {
    #[inline]
    fn mappings(&self) -> &[MemoryMap] {
        (**self).mappings()
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read(addr, buf)
    }

    #[inline]
    fn search(
        &self,
        addr: PhysicalAddress,
        page_size: u64,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> MemoryAccessResult<Option<u64>> {
        (**self).search(addr, page_size, finder, buf)
    }

    #[cfg(feature = "std")]
    #[inline]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        (**self).dump(writer)
    }
}

impl<M: Memory + ?Sized> Memory for alloc::boxed::Box<M> {
    #[inline]
    fn mappings(&self) -> &[MemoryMap] {
        (**self).mappings()
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read(addr, buf)
    }

    #[inline]
    fn search(
        &self,
        addr: PhysicalAddress,
        page_size: u64,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> MemoryAccessResult<Option<u64>> {
        (**self).search(addr, page_size, finder, buf)
    }

    #[cfg(feature = "std")]
    #[inline]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        (**self).dump(writer)
    }
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct File {
    file: sync_file::RandomAccessFile,
    start: u64,
    mapping: MemoryMap,
}

#[cfg(feature = "std")]
impl File {
    #[inline]
    pub fn new(file: fs::File, start: u64, end: u64) -> Self {
        let file = sync_file::RandomAccessFile::from(file);
        let mapping = MemoryMap {
            start: PhysicalAddress(0),
            end: PhysicalAddress(end - start),
        };
        Self {
            file,
            start,
            mapping,
        }
    }

    #[inline]
    pub fn open<P: AsRef<Path>>(path: P, start: u64, end: u64) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        Ok(Self::new(file, start, end))
    }

    #[inline]
    pub fn size(&self) -> u64 {
        self.mapping.end.0
    }
}

#[cfg(feature = "std")]
impl Memory for File {
    #[inline]
    fn mappings(&self) -> &[MemoryMap] {
        core::slice::from_ref(&self.mapping)
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        use sync_file::ReadAt;

        if !self.is_valid(addr, buf.len()) {
            return Err(MemoryAccessError::OutOfBounds);
        }

        let offset = self.start + addr.0;
        self.file.read_exact_at(buf, offset)?;
        Ok(())
    }
}
