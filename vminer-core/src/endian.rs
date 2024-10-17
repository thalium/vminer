pub trait Endianness {
    fn as_runtime_endian(&self) -> RuntimeEndian;

    #[inline]
    fn is_little_endian(&self) -> bool {
        self.as_runtime_endian() == RuntimeEndian::Little
    }

    #[inline]
    fn read_u16(&self, n: u16) -> u16 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u16::from_le(n),
            RuntimeEndian::Big => u16::from_be(n),
        }
    }

    #[inline]
    fn read_u32(&self, n: u32) -> u32 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u32::from_le(n),
            RuntimeEndian::Big => u32::from_be(n),
        }
    }

    #[inline]
    fn read_u64(&self, n: u64) -> u64 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u64::from_le(n),
            RuntimeEndian::Big => u64::from_be(n),
        }
    }

    #[inline]
    fn read_i16(&self, n: i16) -> i16 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => i16::from_le(n),
            RuntimeEndian::Big => i16::from_be(n),
        }
    }

    #[inline]
    fn read_i32(&self, n: i32) -> i32 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => i32::from_le(n),
            RuntimeEndian::Big => i32::from_be(n),
        }
    }

    #[inline]
    fn read_i64(&self, n: i64) -> i64 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => i64::from_le(n),
            RuntimeEndian::Big => i64::from_be(n),
        }
    }

    #[inline]
    fn read_u16_bytes(&self, bytes: [u8; 2]) -> u16 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u16::from_le_bytes(bytes),
            RuntimeEndian::Big => u16::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_u32_bytes(&self, bytes: [u8; 4]) -> u32 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u32::from_le_bytes(bytes),
            RuntimeEndian::Big => u32::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_u64_bytes(&self, bytes: [u8; 8]) -> u64 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => u64::from_le_bytes(bytes),
            RuntimeEndian::Big => u64::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_i16_bytes(&self, bytes: [u8; 2]) -> i16 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => i16::from_le_bytes(bytes),
            RuntimeEndian::Big => i16::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_i32_bytes(&self, bytes: [u8; 4]) -> i32 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => i32::from_le_bytes(bytes),
            RuntimeEndian::Big => i32::from_be_bytes(bytes),
        }
    }

    #[inline]
    fn read_i64_bytes(&self, bytes: [u8; 8]) -> i64 {
        match self.as_runtime_endian() {
            RuntimeEndian::Little => i64::from_le_bytes(bytes),
            RuntimeEndian::Big => i64::from_be_bytes(bytes),
        }
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
