#![allow(non_snake_case)]

use crate::os::pointer::{self, HasLayout, StructOffset};
use core::marker::PhantomData;
use ibc::{IceResult, PhysicalAddress, VirtualAddress};

type Pointer<T> = pointer::RawPointer<T>;

pub(crate) struct FastSymbols {
    pub KiImplementedPhysicalBits: u64,
    pub PsActiveProcessHead: u64,
    pub PsLoadedModuleList: u64,
}

macro_rules! impl_has_layout {
    (impl HasLayout<$struct_name:ident, kernel> = $kname:ident) => {
        impl<B: ibc::Backend> HasLayout<$struct_name, pointer::KernelSpace> for super::Windows<B> {
            fn get_layout(&self) -> &$struct_name {
                &self.profile().layouts.$kname
            }
        }
    };

    (impl HasLayout<$struct_name:ident, user> = $kname:ident) => {
        impl<B: ibc::Backend> HasLayout<$struct_name, pointer::ProcSpace> for super::Windows<B> {
            fn get_layout(&self) -> &$struct_name {
                &self.profile().layouts.$kname
            }
        }
    };

    (impl HasLayout<$struct_name:ident, all> = $kname:ident) => {
        impl<B: ibc::Backend, Ctx> HasLayout<$struct_name, Ctx> for super::Windows<B> {
            fn get_layout(&self) -> &$struct_name {
                &self.profile().layouts.$kname
            }
        }
    };
}

/// This macro defines Rust types to access kernel structures with type checking
macro_rules! define_structs {
    (
        // The structure to store all layouts
        struct $layouts:ident { .. }

        $(
            // Each structure has to define the name of the matching kernel
            // struct and the fields it wants to access
            #[actual_name($kname:ident)]
            #[define_for($space:tt)]
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
            // First, redefine all fields within `StructOffset`s
            #[non_exhaustive]
            #[allow(non_snake_case)]
            $( #[ $attr ] )*
            pub(crate) struct $struct_name $(<$gen = ()>)? {
                $(
                    $( #[ $field_attr ] )*
                    pub $field: StructOffset<$typ>,
                )*
                $(
                    _typ: PhantomData<$gen>,
                )?
            }

            // Make a constructor
            impl $(<$gen>)? $struct_name $(<$gen>)? {
                fn new(layout: ibc::symbols::Struct) -> IceResult<Self> {
                    Ok(Self {
                        $(
                            $field: StructOffset::new(layout, stringify!($field))?,
                        )*
                        $(
                            _typ: PhantomData::<$gen>,
                        )?
                    })
                }
            }

            $(
                impl<$gen> crate::os::pointer::Monomorphize for $struct_name<$gen> {
                    type Mono = $struct_name;
                }
            )?

            impl_has_layout!(impl HasLayout<$struct_name, $space> = $kname);
        )*

        // Then put all layouts in a single structure
        pub(super) struct $layouts {
            $(
                $kname: $struct_name,
            )*
        }

        impl $layouts {
            fn new(syms: &ibc::ModuleSymbols) -> IceResult<Self> {
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
define_structs! {
    struct Layouts { .. }

    #[actual_name(_CLIENT_ID)]
    #[define_for(kernel)]
    struct ClientId {
        UniqueThread: u64,
    }

    #[actual_name(_EPROCESS)]
    #[define_for(kernel)]
    struct Eprocess {
        ActiveProcessLinks: ListEntry<Eprocess>,
        ImageFileName: [u8; 16],
        ImageFilePointer: Pointer<FileObject>,
        InheritedFromUniqueProcessId: u64,
        Pcb: Kprocess,
        Peb: Pointer<Peb>,
        ThreadListHead: ListEntry<Ethread>,
        UniqueProcessId: u64,
        VadRoot: RtlAvlTree<MmvadShort>,
    }

    #[actual_name(_ETHREAD)]
    #[define_for(kernel)]
    struct Ethread {
        Tcb: Kthread,
        Cid: ClientId,
        ThreadListEntry: ListEntry<Ethread>,
        ThreadName: Pointer<UnicodeString>,
    }

    #[actual_name(_FILE_OBJECT)]
    #[define_for(kernel)]
    struct FileObject {
        FileName: UnicodeString,
    }

    #[actual_name(_KPCR)]
    #[define_for(kernel)]
    struct Kpcr {
        Prcb: Kprcb,
    }

    #[actual_name(_KPRCB)]
    #[define_for(kernel)]
    struct Kprcb {
        CurrentThread: Pointer<Ethread>,
        #[allow(dead_code)]
        KernelDirectoryTableBase: PhysicalAddress,
    }

    #[actual_name(_KPROCESS)]
    #[define_for(kernel)]
    struct Kprocess {
        DirectoryTableBase: PhysicalAddress,
        UserDirectoryTableBase: PhysicalAddress,
    }

    #[actual_name(_KTHREAD)]
    #[define_for(kernel)]
    struct Kthread {
        Process: Pointer<Eprocess>,
    }

    #[actual_name(_LDR_DATA_TABLE_ENTRY)]
    #[define_for(all)]
    struct LdrDataTableEntry {
        BaseDllName: UnicodeString,
        DllBase: VirtualAddress,
        FullDllName: UnicodeString,
        InLoadOrderLinks: ListEntry<LdrDataTableEntry>,
        SizeOfImage: u32,
    }

    #[actual_name(_LIST_ENTRY)]
    #[define_for(all)]
    struct ListEntry<T> {
        Flink: Pointer<ListEntry>,
        #[allow(dead_code)]
        Blink: Pointer<ListEntry>,
    }

    #[actual_name(_MMVAD_SHORT)]
    #[define_for(kernel)]
    struct MmvadShort {
        EndingVpn: u32,
        EndingVpnHigh: u8,
        StartingVpn: u32,
        StartingVpnHigh: u8,
        VadNode: RtlBalancedNode<MmvadShort>,
    }

    #[actual_name(_MMVAD)]
    #[define_for(kernel)]
    struct Mmvad {
        FirstPrototypePte: Pointer<super::memory::MmPte>,
    }

    #[actual_name(_PEB)]
    #[define_for(user)]
    struct Peb {
        Ldr: Pointer<PebLdrData>,
    }

    #[actual_name(_PEB_LDR_DATA)]
    #[define_for(user)]
    struct PebLdrData {
        InLoadOrderModuleList: ListEntry<LdrDataTableEntry>,
    }

    #[actual_name(_RTL_AVL_TREE)]
    #[define_for(kernel)]
    struct RtlAvlTree<T> {
        Root: Pointer<RtlBalancedNode<T>>,
    }

    #[actual_name(_RTL_BALANCED_NODE)]
    #[define_for(kernel)]
    struct RtlBalancedNode<T> {
        Left: Pointer<RtlBalancedNode>,
        Right: Pointer<RtlBalancedNode>,
    }

    #[actual_name(_UNICODE_STRING)]
    #[define_for(all)]
    struct UnicodeString {
        Length: u16,
        Buffer: VirtualAddress,
    }
}

pub struct Profile {
    pub(crate) syms: ibc::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,

    pub(super) layouts: Layouts,
}

impl Profile {
    pub fn new(syms: ibc::SymbolsIndexer) -> IceResult<Self> {
        let kernel = syms.get_lib("ntkrnlmp.pdb")?;
        let layouts = Layouts::new(&kernel)?;
        let KiImplementedPhysicalBits = kernel.get_address("KiImplementedPhysicalBits")?.0;
        let PsActiveProcessHead = kernel.get_address("PsActiveProcessHead")?.0;
        let PsLoadedModuleList = kernel.get_address("PsLoadedModuleList")?.0;

        Ok(Self {
            syms,
            fast_syms: FastSymbols {
                KiImplementedPhysicalBits,
                PsActiveProcessHead,
                PsLoadedModuleList,
            },
            layouts,
        })
    }
}
