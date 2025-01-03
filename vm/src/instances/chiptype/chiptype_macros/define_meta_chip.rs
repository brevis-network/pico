#[macro_export]
macro_rules! define_meta_chip {
    (MemoryInitialize, $chip_type:ident, $F:ident) => {
        MetaChip::new(Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
            MemoryChipType::Initialize,
        )))
    };

    (MemoryFinalize, $chip_type:ident, $F:ident) => {
        MetaChip::new(Self::MemoryFinalize(MemoryInitializeFinalizeChip::new(
            MemoryChipType::Finalize,
        )))
    };

    (SyscallRiscv, $chip_type:ident, $F:ident) => {
        MetaChip::new(Self::SyscallRiscv(SyscallChip::riscv()))
    };
    (SyscallPrecompile, $chip_type:ident, $F:ident) => {
        MetaChip::new(Self::SyscallPrecompile(SyscallChip::precompile()))
    };

    ($variant:ident, $chip_type:ident, $F:ident) => {
        MetaChip::new(Self::$variant($chip_type::default()))
    };
}
