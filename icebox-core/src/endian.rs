pub trait Endianness {
    fn as_runtime_endian(&self) -> RuntimeEndian;

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.as_runtime_endian() == RuntimeEndian::Little
    }

    #[inline]
    fn read_u16(&self, bytes: [u8; 2]) -> u16 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u16::from_le_bytes(bytes),
            RuntimeEndian::Big => u16::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_i16(&self, bytes: [u8; 2]) -> i16 {
        self.read_u16(bytes) as _
    }

    #[inline]
    fn read_u32(&self, bytes: [u8; 4]) -> u32 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u32::from_le_bytes(bytes),
            RuntimeEndian::Big => u32::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_i32(&self, bytes: [u8; 4]) -> i32 {
        self.read_u32(bytes) as _
    }

    #[inline]
    fn read_u64(&self, bytes: [u8; 8]) -> u64 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u64::from_le_bytes(bytes),
            RuntimeEndian::Big => u64::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_i64(&self, bytes: [u8; 8]) -> i64 {
        self.read_u64(bytes) as _
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LittleEndian;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigEndian;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEndian {
    Big,
    Little,
}

impl Endianness for LittleEndian {
    #[inline]
    fn as_runtime_endian(&self) -> RuntimeEndian {
        RuntimeEndian::Little
    }
}

impl Endianness for BigEndian {
    #[inline]
    fn as_runtime_endian(&self) -> RuntimeEndian {
        RuntimeEndian::Big
    }
}

impl Endianness for RuntimeEndian {
    #[inline]
    fn as_runtime_endian(&self) -> RuntimeEndian {
        *self
    }
}
