use ibc::{Backend, IceResult, PhysicalAddress, VirtualAddress};

#[derive(Debug)]
pub struct Windows<B> {
    backend: B,
    kpgd: PhysicalAddress,
}

impl<B: Backend> Windows<B> {
    pub fn create(backend: B) -> IceResult<Self> {
        let kpgd = backend.find_kernel_pgd(false, &[VirtualAddress(0xfffff78000000000)])?;
        println!("{kpgd:x?}");
        Ok(Self { backend, kpgd })
    }

    fn read_kernel_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.backend.read_virtual_memory(self.kpgd, addr, buf)
    }

    pub fn test(&self) {
        const KERNEL_PDB: &[u8] = b"ntkrnlmp.pdb\0";

        let kpgd = ibc::PhysicalAddress(self.kpgd.0 & !ibc::mask(12));
        let mut table = [0u64; 512];
        self.backend
            .read_memory(kpgd, bytemuck::bytes_of_mut(&mut table))
            .unwrap();

        let mut buf = vec![0; 0];
        // println!("{:x?}", self.backend.virtual_to_physical(self.kpgd, VirtualAddress(0xffff_ff)));
        for addr in self
            .backend
            .iter_in_kernel_memory(self.kpgd, b"MZ")
            .map_while(|addr| addr.ok())
            .filter(|addr| addr.0 & 0xfff == 0)
        {
            buf.resize(0x1000, 0);
            self.read_kernel_memory(addr, &mut buf).unwrap();

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
                let _ = self.read_kernel_memory(
                    addr + i as u64 * 0x1000,
                    &mut buf[i * 0x1000..(i + 1) * 0x1000],
                );
            }

            let index = if let Some(i) = memchr::memmem::find(&buf, b"RSDS") {
                i
            } else {
                continue;
            };

            if &buf[index + 0x18..index + 0x18 + KERNEL_PDB.len()] != KERNEL_PDB {
                continue;
            }

            eprintln!(
                "{:?}",
                String::from_utf8_lossy(&buf[index + 0x18..index + 0x18 + KERNEL_PDB.len()])
            );
            eprintln!("GUID: {:x?}", &buf[index + 0x4..index + 0x14]);

            break;
        }
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
