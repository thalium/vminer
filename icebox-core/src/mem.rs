use super::{GuestPhysAddr, MemoryAccessError, MemoryAccessResult};

#[cfg(feature = "std")]
use std::{fs, io, path::Path};

pub trait Memory {
    fn size(&self) -> u64;

    fn read(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()>;

    #[cfg(feature = "std")]
    fn dump(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        let mut buffer = [0; 1 << 16];
        let size = self.size();

        for addr in (0..size).step_by(buffer.len() as _) {
            self.read(GuestPhysAddr(addr), &mut buffer)?;
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
    fn read(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (|| {
            let offset = addr.0.try_into().ok()?;
            let this = self.get(offset..)?;
            let len = buf.len();
            (this.len() >= len).then(|| buf.copy_from_slice(&this[..len]))
        })()
        .ok_or(MemoryAccessError::OutOfBounds)
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
    fn read(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read(addr, buf)
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
    fn read(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read(addr, buf)
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
    fn read(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read(addr, buf)
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
    fn read(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        use sync_file::ReadAt;

        let offset = self.start + addr.0;
        if offset + (buf.len() as u64) > self.end {
            return Err(MemoryAccessError::OutOfBounds);
        }
        self.file.read_exact_at(buf, offset)?;
        Ok(())
    }
}
