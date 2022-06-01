use super::{MemoryAccessError, MemoryAccessResult, PhysicalAddress};

#[cfg(feature = "std")]
use std::{fs, io, path::Path};

/// A trait to specify how to read physical memory from a guest
///
/// This trait defines additional optional methods for specialisation
pub trait Memory {
    fn size(&self) -> u64;

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
        let size = self.size();

        for addr in (0..size).step_by(buffer.len() as _) {
            self.read(PhysicalAddress(addr), &mut buffer)?;
            writer.write_all(&buffer)?;
        }

        Ok(())
    }
}

impl Memory for [u8] {
    #[inline]
    fn size(&self) -> u64 {
        self.len() as u64
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (|| {
            let offset = addr.0.try_into().ok()?;
            let this = self.get(offset..)?;
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
            self.get(offset..max)
        })()
        .ok_or(MemoryAccessError::OutOfBounds)?;

        Ok(finder.find(this).map(|i| i as u64))
    }

    #[cfg(feature = "std")]
    #[inline]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        writer.write_all(self)
    }
}

impl Memory for alloc::vec::Vec<u8> {
    #[inline]
    fn size(&self) -> u64 {
        (**self).size()
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

impl<M: Memory + ?Sized> Memory for &'_ M {
    #[inline]
    fn size(&self) -> u64 {
        (**self).size()
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
    fn size(&self) -> u64 {
        (**self).size()
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read(addr, buf)
    }

    #[cfg(feature = "std")]
    #[inline]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        (**self).dump(writer)
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
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct File {
    file: sync_file::RandomAccessFile,
    start: u64,
    end: u64,
}

#[cfg(feature = "std")]
impl File {
    #[inline]
    pub fn new(file: fs::File, start: u64, end: u64) -> Self {
        let file = sync_file::RandomAccessFile::from(file);
        Self { file, start, end }
    }

    #[inline]
    pub fn open<P: AsRef<Path>>(path: P, start: u64, end: u64) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        Ok(Self::new(file, start, end))
    }
}

#[cfg(feature = "std")]
impl Memory for File {
    #[inline]
    fn size(&self) -> u64 {
        self.end - self.start
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        use sync_file::ReadAt;

        let offset = self.start + addr.0;
        if offset + (buf.len() as u64) > self.end {
            return Err(MemoryAccessError::OutOfBounds);
        }
        self.file.read_exact_at(buf, offset)?;
        Ok(())
    }
}
