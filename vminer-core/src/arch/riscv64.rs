use bytemuck::{Pod, Zeroable};

use super::runtime;
use crate::{endian::LittleEndian, PhysicalAddress, VcpuResult, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub struct Riscv64;

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
pub struct Vcpu {
    pub registers: Registers,
    pub special_registers: SpecialRegisters,
    pub other_registers: OtherRegisters,
}

struct MmuDesc;

impl super::MmuDesc for MmuDesc {
    #[inline]
    fn is_valid(mmu_entry: crate::addr::MmuEntry) -> bool {
        todo!()
    }

    #[inline]
    fn is_large(mmu_entry: crate::addr::MmuEntry) -> bool {
        todo!()
    }
}

impl super::Architecture for Riscv64 {
    type Endian = LittleEndian;

    type Registers = Registers;
    type SpecialRegisters = SpecialRegisters;
    type OtherRegisters = OtherRegisters;

    #[inline]
    fn into_runtime(self) -> runtime::Architecture {
        runtime::Architecture::Riscv64(self)
    }

    #[inline]
    fn endianness(&self) -> LittleEndian {
        LittleEndian
    }

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> crate::TranslationResult<PhysicalAddress> {
        super::virtual_to_physical::<MmuDesc, M>(memory, mmu_addr, addr)
    }

    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        vcpus: &(impl super::HasVcpus<Arch = Self> + ?Sized),
        use_per_cpu: bool,
        additional: &[VirtualAddress],
    ) -> crate::VmResult<Option<PhysicalAddress>> {
        for vcpu in vcpus.iter_vcpus() {
            if vcpus.instruction_pointer(vcpu)?.is_kernel() {
                return Ok(Some(vcpus.pgd(vcpu)?));
            }
        }

        // To check if a TTBR is valid, try to translate valid kernel addresses with it
        let addresses = &[additional];
        let test = super::make_address_test(vcpus, memory, use_per_cpu, addresses);

        // // Try pages near a "wrong" TTBR1
        // if let Some(vcpu) = vcpus
        //     .iter_vcpus()
        //     .find(|vcpu| vcpus.instruction_pointer( vcpu).is_kernel())
        // {
        //     for i in -5..6 {
        //         let ttbr1 = vcpu.cleaned_ttbr1() + i * 4096i64;
        //         if test(ttbr1) {
        //             return Some(ttbr1);
        //         }
        //     }
        // }

        Ok(super::try_all_addresses(test))
    }

    fn find_in_kernel_memory_raw<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        base_search_addr: VirtualAddress,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        super::find_in_kernel_memory_raw::<MmuDesc, M>(
            memory,
            mmu_addr,
            base_search_addr,
            finder,
            buf,
        )
    }

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        super::find_in_kernel_memory::<MmuDesc, M>(memory, mmu_addr, needle, self.kernel_base())
    }

    #[inline]
    fn kernel_base(&self) -> VirtualAddress {
        todo!()
    }

    fn register_by_name<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: super::VcpuId,
        name: &str,
    ) -> VcpuResult<u64> {
        let regs = vcpus.registers(vcpu)?;

        'x: {
            return Ok(match name {
                "pc" => regs.pc,
                "ra" => regs.ra,
                "sp" => regs.sp,
                "gp" => regs.gp,
                "tp" => regs.tp,
                _ => break 'x,
            });
        }

        let reg = (|| {
            let (l, n) = name.split_at_checked(1)?;
            let n: usize = n.parse().ok()?;

            Some(match (l, n) {
                ("x", 0) => 0,
                ("x", n) => *regs.as_array().get(n)?,
                ("a", n) => match n {
                    0 => regs.a0,
                    1 => regs.a1,
                    2 => regs.a2,
                    3 => regs.a3,
                    4 => regs.a4,
                    5 => regs.a5,
                    6 => regs.a6,
                    7 => regs.a7,
                    _ => return None,
                },
                ("t", n) => match n {
                    0 => regs.t0,
                    1 => regs.t1,
                    2 => regs.t2,
                    3 => regs.t3,
                    4 => regs.t4,
                    5 => regs.t5,
                    6 => regs.t6,
                    _ => return None,
                },
                ("s", n) => match n {
                    0 => regs.s0,
                    1 => regs.s1,
                    2 => regs.s2,
                    3 => regs.s3,
                    4 => regs.s4,
                    5 => regs.s5,
                    6 => regs.s6,
                    7 => regs.s7,
                    8 => regs.s8,
                    9 => regs.s9,
                    10 => regs.s10,
                    11 => regs.s11,
                    _ => return None,
                },
                _ => return None,
            })
        })();

        reg.ok_or(crate::VcpuError::UnknownRegister)
    }

    fn instruction_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<VirtualAddress> {
        let registers = vcpus.registers(vcpu)?;
        Ok(VirtualAddress(registers.pc))
    }

    fn stack_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<VirtualAddress> {
        let sp = vcpus.registers(vcpu)?.sp;
        Ok(VirtualAddress(sp))
    }

    fn base_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<Option<VirtualAddress>> {
        let s0 = vcpus.registers(vcpu)?.s0;
        Ok(Some(VirtualAddress(s0)))
    }

    fn pgd<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<PhysicalAddress> {
        use super::MmuDesc as _;

        let ttbr = 0;

        Ok(PhysicalAddress(ttbr & crate::mask(MmuDesc::ADDR_BITS)))
    }

    fn kernel_per_cpu<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        _vcpus: &Vcpus,
        _vcpu: crate::VcpuId,
    ) -> VcpuResult<Option<VirtualAddress>> {
        Ok(None)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Registers {
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    pub tp: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub s0: u64,
    pub s1: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
    pub t3: u64,
    pub t4: u64,
    pub t5: u64,
    pub t6: u64,
}

impl Registers {
    pub fn as_array(&self) -> &[u64; 32] {
        bytemuck::must_cast_ref(self)
    }
}

/// A curated list of additional useful registers
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct SpecialRegisters {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct OtherRegisters;

impl From<Registers> for super::runtime::Registers {
    #[inline]
    fn from(regs: Registers) -> Self {
        Self::Riscv64(regs)
    }
}

impl From<SpecialRegisters> for super::runtime::SpecialRegisters {
    #[inline]
    fn from(regs: SpecialRegisters) -> Self {
        Self::Riscv64(regs)
    }
}

impl From<OtherRegisters> for super::runtime::OtherRegisters {
    #[inline]
    fn from(regs: OtherRegisters) -> Self {
        Self::Riscv64(regs)
    }
}
