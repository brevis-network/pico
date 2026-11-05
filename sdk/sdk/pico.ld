/*
 * Pico guest linker script, for GNU ld and LLD.
 *
 * Memory layout (documented in docs/guest-runtime.md):
 *
 *   0x00010000  lowest loadable address; below it no access is provable
 *   0x00200800  .text, then read-only data, then .data / .bss
 *   _heap_start heap, growing up, to _heap_end
 *   _heap_end   stack guard (__pico_stack_guard_size bytes)
 *   _stack_bottom
 *               stack (__pico_stack_size bytes), growing down
 *   0x78000000  _stack_top: the end of guest memory
 *
 * The four values below are the emulator's too: vm/src/primitives/layout.rs holds the same
 * constants, and its test fails if they differ from these. Change both together.
 */

/* 64-bit output: GNU ld built for several RISC-V targets, such as riscv-none-elf-ld, defaults to
 * 32-bit and refuses the RV64 objects otherwise. */
OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

__pico_memory_size = 0x78000000;
__pico_text_start = 0x00200800;
__pico_stack_size = 0x00800000;
__pico_stack_guard_size = 0x00010000;

_stack_top = __pico_memory_size;
_stack_bottom = _stack_top - __pico_stack_size;
_heap_end = _stack_bottom - __pico_stack_guard_size;

/* Code, read-only data and writable data in separate segments, so no segment is both writable
 * and executable and the executable one holds instructions only. */
PHDRS
{
    text   PT_LOAD FLAGS(5); /* R X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R W */
}

SECTIONS
{
    . = __pico_text_start;

    .text : {
        *(.text.init)
        *(.text .text.* .gnu.linkonce.t.*)
    } :text
    .init : { KEEP(*(SORT_NONE(.init))) } :text
    .fini : { KEEP(*(SORT_NONE(.fini))) } :text

    . = ALIGN(0x1000);
    .rodata : {
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.srodata .srodata.*)
    } :rodata
    .eh_frame_hdr : { *(.eh_frame_hdr) } :rodata
    .eh_frame : { KEEP(*(.eh_frame)) *(.eh_frame.*) } :rodata
    .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) } :rodata

    /* The constructor and destructor tables `_start` walks. Read-only once linked: the image is
     * static, so nothing relocates them at run time. */
    .preinit_array : {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN(__preinit_array_end = .);
    } :rodata
    .init_array : {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array .ctors))
        PROVIDE_HIDDEN(__init_array_end = .);
    } :rodata
    .fini_array : {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array .dtors))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } :rodata
    .data.rel.ro : { *(.data.rel.ro.local* .data.rel.ro .data.rel.ro.*) } :rodata

    . = ALIGN(0x1000);
    .data : {
        *(.data .data.* .gnu.linkonce.d.*)
    } :data
    /* gp addresses +-2 KiB around itself, so point it 2 KiB into the small-data area. */
    .sdata : {
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.* .gnu.linkonce.s.*)
    } :data
    .sbss : {
        *(.sbss .sbss.* .gnu.linkonce.sb.*)
        *(.scommon)
    } :data
    .bss : {
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    } :data

    . = ALIGN(16);
    _end = .;
    _heap_start = .;

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.gnu_debuglink)
        *(.gnu.lto_*)
    }
}

ASSERT(_heap_start <= _heap_end, "the program image reaches into the stack region")
