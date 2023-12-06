use super::Linux;
use crate::os::pointer::{self, HasLayout, HasOffset};
use core::marker::PhantomData;
use ibc::{IceResult, VirtualAddress};

type Pointer<T> = pointer::RawPointer<T>;

pub(crate) struct FastSymbols {
    pub(crate) per_cpu_offset: VirtualAddress,
    pub(crate) current_task: Option<u64>,

    pub(super) init_task: ibc::VirtualAddress,
    pub linux_banner: ibc::VirtualAddress,
}

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
            struct $struct_name:ident $(<$gen:ident>)? {
                $(
                    $( #[ $field_attr:meta ] )*
                    $field:ident : $typ:ty,
                )*
            }
        )*
    ) => {
        $(
            mod $kname {
                use super::*;

                pub const KERNEL_NAME: &str = stringify!($kname);

                // First, redefine all fields within `StructOffset`s
                #[non_exhaustive]
                #[allow(non_snake_case)]
                $( #[ $attr ] )*
                pub(crate) struct $struct_name $(<$gen = ()>)? {
                    $(
                        $( #[ $field_attr ] )*
                        pub $field: $field,
                    )*
                    $(
                        _typ: PhantomData<$gen>,
                    )?
                }

                // For each field, define a struct that knows how to get its offset
                $(
                    #[derive(Clone, Copy)]
                    #[allow(non_camel_case_types)]
                    pub(crate) struct $field(Option<u64>);

                    impl $field {
                        const NAME: &'static str = stringify!($field);
                    }

                    impl HasOffset for $field {
                        type Target = $typ;

                        fn from_layout(layout: ibc::symbols::StructRef) -> Self {
                            Self(layout.find_offset(Self::NAME))
                        }

                        fn offset(self) -> IceResult<u64> {
                            match self.0 {
                                Some(o) => Ok(o),
                                None => Err(ibc::IceError::missing_field(Self::NAME, KERNEL_NAME)),
                            }
                        }
                    }
                )*

                // Make a constructor
                impl $(<$gen>)? $struct_name $(<$gen>)? {
                    pub fn new(layout: ibc::symbols::StructRef) -> Self {
                        Self {
                            $(
                                $field: <$field>::from_layout(layout),
                            )*
                            $(
                                _typ: PhantomData::<$gen>,
                            )?
                        }
                    }
                }

                $(
                    impl<$gen> crate::os::pointer::Monomorphize for $struct_name<$gen> {
                        type Mono = $struct_name;
                    }
                )?

                // Make the struct easily available
                impl<B: ibc::Backend> HasLayout<$struct_name, pointer::KernelSpace> for Linux<B> {
                    fn get_layout(&self) -> IceResult<&$struct_name> {
                        match &self.profile.layouts.$kname {
                            Some(l) => Ok(l),
                            None => Err(ibc::IceError::missing_symbol(stringify!($struct_name))),
                        }
                    }
                }
            }

            #[allow(unused)]
            pub(super) use $kname::$struct_name;
        )*

        // Then put all layouts in a single structure
        pub(super) struct $layouts {
            $(
                $kname: Option<$struct_name>,
            )*
        }

        impl $layouts {
            fn new(syms: &ibc::ModuleSymbols) -> IceResult<Self> {
                Ok(Self {
                    $(
                        $kname: syms.get_struct($kname::KERNEL_NAME).map(|layout| $kname::$struct_name::new(layout)),
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
    struct ListHead<T> {
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
        children: ListHead<TaskStruct>,
        comm: [u8; 16],
        flags: u32,
        group_leader: Pointer<TaskStruct>,
        mm: Pointer<MmStruct>,
        pid: u32,
        real_parent: Pointer<TaskStruct>,
        sibling: ListHead<TaskStruct>,
        tasks: ListHead<TaskStruct>,
        tgid: u32,
        thread_group: ListHead<TaskStruct>,
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
    pub(crate) syms: ibc::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,

    pub(super) layouts: Layouts,
}

impl Profile {
    pub fn new(syms: ibc::SymbolsIndexer) -> IceResult<Self> {
        let symbols = syms.require_module("System.map")?;
        let per_cpu_offset = symbols.require_address("__per_cpu_offset")?;
        let current_task = symbols.get_address("current_task").map(|sym| sym.0);
        let init_task = symbols.require_address("init_task")?;
        let linux_banner = symbols.require_address("linux_banner")?;

        let types = syms
            .require_module("vmlinux")
            .or_else(|_| syms.require_module("module.ko"))?;

        let layouts = Layouts::new(types)?;

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
