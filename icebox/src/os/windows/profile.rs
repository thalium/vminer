#![allow(non_snake_case)]

use ice::PhysicalAddress;

use crate::core::{self as ice, IceResult, VirtualAddress};
use core::marker::PhantomData;

pub(crate) struct FastSymbols {
    pub PsActiveProcessHead: u64,
}

pub struct StructOffset<T> {
    pub offset: u64,
    _type: PhantomData<T>,
}

impl<T> Clone for StructOffset<T> {
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

    fn from_offset(offset: u64) -> Self {
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
    pub const fn new(addr: VirtualAddress) -> Self {
        Self {
            addr,
            _typ: PhantomData,
        }
    }

    pub const fn is_null(self) -> bool {
        self.addr.is_null()
    }
}

impl<T> Clone for Pointer<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pointer<T> {}

impl<T> PartialEq for Pointer<T> {
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
            #[allow(non_snake_case)]
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
            impl<B: ice::Backend> super::HasStruct<$struct_name> for super::Windows<B> {
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

        impl Layouts {
            fn new(syms: &ice::SymbolsIndexer) -> IceResult<Self> {
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

    #[kernel_name(_CLIENT_ID)]
    struct ClientId {
        UniqueThread: u64,
    }

    #[kernel_name(_EPROCESS)]
    struct Eprocess {
        ActiveProcessLinks: ListEntry,
        Pcb: Kprocess,
        UniqueProcessId: u64,
        ImageFileName: [u8; 16],
        InheritedFromUniqueProcessId: u64,
        ThreadListHead: ListEntry,
        VadRoot: RtlAvlTree,
    }

    #[kernel_name(_ETHREAD)]
    struct Ethread {
        Tcb: Kthread,
        Cid: ClientId,
        ThreadListEntry: ListEntry,
        ThreadName: Pointer<UnicodeString>,
    }

    #[kernel_name(_KPCR)]
    struct Kpcr {
        Prcb: Kprcb,
    }

    #[kernel_name(_KPRCB)]
    struct Kprcb {
        CurrentThread: Pointer<Ethread>,
        #[allow(dead_code)]
        KernelDirectoryTableBase: PhysicalAddress,
    }

    #[kernel_name(_KPROCESS)]
    struct Kprocess {
        UserDirectoryTableBase: PhysicalAddress,
        DirectoryTableBase: PhysicalAddress,
    }

    #[kernel_name(_LIST_ENTRY)]
    struct ListEntry {
        Flink: Pointer<ListEntry>,
        #[allow(dead_code)]
        Blink: Pointer<ListEntry>,
    }

    #[kernel_name(_MMVAD_SHORT)]
    struct MmvadShort {
        EndingVpn: u32,
        EndingVpnHigh: u32,
        StartingVpn: u32,
        StartingVpnHigh: u32,
        VadNode: RtlBalancedNode,
    }

    #[kernel_name(_KTHREAD)]
    struct Kthread {
        Process: Pointer<Eprocess>,
    }

    #[kernel_name(_RTL_AVL_TREE)]
    struct RtlAvlTree {
        Root: Pointer<RtlBalancedNode>,
    }

    #[kernel_name(_RTL_BALANCED_NODE)]
    struct RtlBalancedNode {
        Left: Pointer<RtlBalancedNode>,
        Right: Pointer<RtlBalancedNode>,
    }

    #[kernel_name(_UNICODE_STRING)]
    struct UnicodeString {
        Length: u16,
        Buffer: VirtualAddress,
    }
}

impl From<Pointer<Ethread>> for Pointer<Kthread> {
    fn from(p: Pointer<Ethread>) -> Self {
        Pointer::new(p.addr)
    }
}

impl From<Pointer<Eprocess>> for Pointer<Kprocess> {
    fn from(p: Pointer<Eprocess>) -> Self {
        Pointer::new(p.addr)
    }
}

pub struct Profile {
    #[allow(unused)]
    pub(crate) syms: ice::SymbolsIndexer,
    #[allow(dead_code)]
    pub(crate) fast_syms: FastSymbols,

    pub(super) layouts: Layouts,
}

impl Profile {
    pub fn new(syms: ice::SymbolsIndexer) -> IceResult<Self> {
        let layouts = Layouts::new(&syms)?;

        let kernel = syms.get_lib("ntkrnlmp.exe")?;
        let PsActiveProcessHead = kernel.get_address("PsActiveProcessHead")?.0;

        Ok(Self {
            syms,
            fast_syms: FastSymbols {
                PsActiveProcessHead,
            },
            layouts,
        })
    }
}
