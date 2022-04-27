use crate::core::{self as ice, IceResult, VirtualAddress};
use core::marker::PhantomData;

pub(crate) struct FastSymbols {
    pub(crate) per_cpu_offset: VirtualAddress,
    pub(crate) current_task: Option<u64>,

    pub(super) init_task: ice::VirtualAddress,
    pub linux_banner: ice::VirtualAddress,
}

pub struct StructOffset<T> {
    pub offset: u64,
    _type: PhantomData<T>,
}

impl<T> Clone for StructOffset<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for StructOffset<T> {}

impl<T> StructOffset<T> {
    fn new(layout: ice::symbols::Struct, field_name: &str) -> IceResult<Self> {
        let offset = layout.find_offset(field_name)?;
        Ok(Self::from_offset(offset))
    }

    #[inline]
    const fn from_offset(offset: u64) -> Self {
        Self {
            offset,
            _type: PhantomData,
        }
    }
}

pub(crate) struct Pointer<T> {
    pub addr: VirtualAddress,
    _typ: PhantomData<T>,
}

impl<T> Pointer<T> {
    #[inline]
    pub const fn new(addr: VirtualAddress) -> Self {
        Self {
            addr,
            _typ: PhantomData,
        }
    }

    #[inline]
    pub const fn is_null(self) -> bool {
        self.addr.is_null()
    }
}

impl<T> Clone for Pointer<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pointer<T> {}

impl<T> PartialEq for Pointer<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl<T> Eq for Pointer<T> {}

/// This macro defines Rust types to access kernel structures with type checking
macro_rules! define_kernel_structs {
    (
        // The structure to store all layouts
        struct $layouts:ident { .. }

        $(
            // Each structure has to define the name of the matching kernel
            // struct and the fields it wants to access
            #[kernel_name($kname:ident)]
            $( #[ $attr:meta ] )*
            struct $struct_name:ident {
                $(
                    $( #[ $field_attr:meta ] )*
                    $field:ident : $typ:ty,
                )*
            }
        )*
    ) => {
        $(
            // First, redefine all fields within `StructOffset`s
            #[non_exhaustive]
            $( #[ $attr ] )*
            pub(crate) struct $struct_name {
                $(
                    $( #[ $field_attr ] )*
                    pub $field: StructOffset<$typ>,
                )*
            }

            // Make a constructor
            impl $struct_name {
                fn new(layout: ice::symbols::Struct) -> IceResult<Self> {
                    Ok(Self {
                        $(
                            $field: StructOffset::new(layout, stringify!($field))?,
                        )*
                    })
                }
            }

            // Make the struct easily available
            impl<B: ice::Backend> super::HasStruct<$struct_name> for super::Linux<B> {
                fn get_struct_layout(&self) -> &$struct_name {
                    &self.profile.layouts.$kname
                }
            }
        )*

        // Then put all layouts in a single structure
        pub(super) struct $layouts {
            $(
                $kname: $struct_name,
            )*
        }

        impl $layouts {
            fn new(syms: &ice::ModuleSymbols) -> IceResult<Self> {
                Ok(Self {
                    $(
                        $kname: $struct_name::new(syms.get_struct(stringify!($kname))?)?,
                    )*
                })
            }
        }
    };
}

// Please keep all these lists in alphetical order
define_kernel_structs! {
    struct Layouts { .. }

    #[kernel_name(dentry)]
    struct Dentry {
        d_name: Qstr,
        d_parent: Pointer<Dentry>,
    }

    #[kernel_name(file)]
    struct File {
        f_path: Path,
    }

    #[kernel_name(list_head)]
    struct ListHead {
        next: Pointer<ListHead>,
        #[allow(dead_code)]
        prev: Pointer<ListHead>,
    }

    #[kernel_name(mm_struct)]
    struct MmStruct {
        exe_file: Pointer<File>,
        mmap: Pointer<VmAreaStruct>,
        pgd: VirtualAddress,
    }

    #[kernel_name(path)]
    struct Path {
        dentry: Pointer<Dentry>,
    }

    #[kernel_name(qstr)]
    struct Qstr {
        name: VirtualAddress,
    }

    #[kernel_name(task_struct)]
    struct TaskStruct {
        active_mm: Pointer<MmStruct>,
        children: ListHead,
        comm: [u8; 16],
        flags: u32,
        group_leader: Pointer<TaskStruct>,
        mm: Pointer<MmStruct>,
        pid: u32,
        real_parent: Pointer<TaskStruct>,
        sibling: ListHead,
        tasks: ListHead,
        tgid: u32,
        thread_group: ListHead,
    }

    #[kernel_name(vm_area_struct)]
    struct VmAreaStruct {
        vm_end: VirtualAddress,
        vm_file: Pointer<File>,
        vm_flags: u64,
        vm_next: Pointer<VmAreaStruct>,
        vm_start: VirtualAddress,
        vm_pgoff: u64,
    }
}

pub struct Profile {
    #[allow(unused)]
    pub(crate) syms: ice::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,

    pub(super) layouts: Layouts,
}

impl Profile {
    pub fn new(syms: ice::SymbolsIndexer) -> IceResult<Self> {
        let symbols = syms.get_lib("System.map")?;
        let per_cpu_offset = symbols.get_address("__per_cpu_offset")?;
        let current_task = symbols.get_address("current_task").ok().map(|sym| sym.0);
        let init_task = symbols.get_address("init_task")?;
        let linux_banner = symbols.get_address("linux_banner")?;

        let types = syms.get_lib("module.ko")?;
        let layouts = Layouts::new(&types)?;

        Ok(Self {
            syms,
            fast_syms: FastSymbols {
                per_cpu_offset,
                current_task,
                init_task,
                linux_banner,
            },
            layouts,
        })
    }
}
