use core::{fmt, mem};
use ibc::{Backend, IceResult, PhysicalAddress, ResultExt, VirtualAddress};

const KERNEL_PDB: &[u8] = b"ntkrnlmp.pdb\0";

#[derive(Debug)]
pub struct Windows<B> {
    backend: B,
    kpgd: PhysicalAddress,
}

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct Codeview {
    magic: [u8; 4],
    guid: Guid,
    age: u32,
    name: [u8; 13],
    _pad: [u8; 3],
}

impl Codeview {
    fn pdb_id(&self) -> String {
        use fmt::Write;

        let mut s = String::with_capacity(33);
        (|| {
            let Guid {
                data1,
                data2,
                data3,
                data4,
            } = self.guid;
            write!(s, "{data1:08X}{data2:04X}{data3:04X}")?;
            for x in data4 {
                write!(s, "{x:02X}")?;
            }
            write!(s, "{}", self.age)
        })()
        .expect("Failed to format GUID");
        s
    }
}

fn find_kernel<B: Backend>(
    backend: &B,
    kpgd: PhysicalAddress,
) -> IceResult<Option<(String, VirtualAddress)>> {
    let mut buf = vec![0; 0];

    for addr in backend
        .iter_in_kernel_memory(kpgd, b"MZ")
        .map_while(|addr| addr.ok())
        .filter(|addr| addr.0 & 0xfff == 0)
    {
        buf.resize(0x1000, 0);
        backend.read_virtual_memory(kpgd, addr, &mut buf).unwrap();

        let pe =
            object::read::pe::PeFile::<'_, object::pe::ImageNtHeaders64>::parse(buf.as_slice())
                .unwrap();
        let size = pe
            .nt_headers()
            .optional_header
            .size_of_image
            .get(object::endian::LittleEndian) as usize;
        buf.resize(size, 0);

        for i in 1..(size / 0x1000) {
            let _ = backend.read_virtual_memory(
                kpgd,
                addr + i as u64 * 0x1000,
                &mut buf[i * 0x1000..(i + 1) * 0x1000],
            );
        }

        let index = match memchr::memmem::find(&buf, b"RSDS") {
            Some(i) => i,
            None => continue,
        };

        let mut codeview: Codeview = bytemuck::Zeroable::zeroed();
        bytemuck::bytes_of_mut(&mut codeview)
            .copy_from_slice(&buf[index..index + mem::size_of::<Codeview>()]);

        if codeview.name != KERNEL_PDB {
            continue;
        }

        return Ok(Some((codeview.pdb_id(), addr)));
    }

    Ok(None)
}

impl<B: Backend> Windows<B> {
    pub fn create(backend: B) -> IceResult<Self> {
        let kpgd = backend.find_kernel_pgd(false, &[VirtualAddress(0xfffff78000000000)])?;
        let (pdb_id, addr) = find_kernel(&backend, kpgd)?.context("failed to find kernel data")?;
        println!("Found kernel at 0x{addr:x} (PDB: {pdb_id})");
        Ok(Self { backend, kpgd })
    }

    #[allow(dead_code)]
    fn read_kernel_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.backend.read_virtual_memory(self.kpgd, addr, buf)
    }
}

impl<B: Backend> ibc::Os for Windows<B> {
    fn init_process(&self) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn current_thread(&self, _cpuid: usize) -> IceResult<ibc::Thread> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_is_kernel(&self, _proc: ibc::Process) -> IceResult<bool> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pid(&self, _proc: ibc::Process) -> IceResult<u32> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_name(&self, _proc: ibc::Process) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pgd(&self, _proc: ibc::Process) -> IceResult<ibc::PhysicalAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_exe(&self, _proc: ibc::Process) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_parent(&self, _proc: ibc::Process) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_child(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_thread(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Thread) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn for_each_process(&self, _f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_vma(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_callstack(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_process(&self, _thread: ibc::Thread) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_id(&self, _thread: ibc::Thread) -> IceResult<u32> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_name(&self, _thread: ibc::Thread) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn path_to_string(&self, _path: ibc::Path) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_file(&self, _vma: ibc::Vma) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_start(&self, _vma: ibc::Vma) -> IceResult<VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_end(&self, _vma: ibc::Vma) -> IceResult<VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_flags(&self, _vma: ibc::Vma) -> IceResult<ibc::VmaFlags> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_offset(&self, _vma: ibc::Vma) -> IceResult<u64> {
        Err(ibc::IceError::unimplemented())
    }

    fn resolve_symbol(&self, _addr: VirtualAddress, _vma: ibc::Vma) -> IceResult<Option<&str>> {
        Err(ibc::IceError::unimplemented())
    }
}
