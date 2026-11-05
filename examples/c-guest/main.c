/*
 * A C guest built without Rust or cargo: compiled with clang, linked against only Pico's static
 * library, libpico_zkvm.a, and its linker script, pico.ld (README.md).
 *
 * The input is one block (read_input). Its first byte picks what the run does; the whole block is
 * echoed to the public output (write_output) first, so every run commits its input.
 *
 *   0  return 0: success
 *   1  return 1: ends abnormally, exit code 1
 *   2  return 256: exit code 256, which an 8-bit exit code would have turned into success
 *   3  abort(): exit code 134
 *   4  a failed assert(): exit code 134
 *
 * Before any of that, main checks that the C constructor below and the C++ one in globals.cpp
 * have run, and returns 7 if not. After main returns, the C++ object's destructor appends "bye"
 * to the output, so a successful run commits its input followed by "bye".
 */
#include <stddef.h>
#include <stdint.h>

/* zkevm-standards' IO interface (zkvm_io.h), from libpico_zkvm.a. */
void read_input(const uint8_t **buf_ptr, size_t *buf_size);
void write_output(const uint8_t *output, size_t size);

/* With no C library, abort and the assert hook come from libpico_zkvm.a too. */
void abort(void);
void __assert_func(const char *file, int line, const char *func, const char *expr);
#define assert(e) ((e) ? (void)0 : __assert_func(__FILE__, __LINE__, __func__, #e))

/* globals.cpp */
int cxx_global_constructed(void);

static int c_constructor_ran;

__attribute__((constructor)) static void c_constructor(void) { c_constructor_ran = 1; }

int main(void) {
    if (!c_constructor_ran || !cxx_global_constructed()) {
        return 7;
    }
    const uint8_t *input;
    size_t size;
    read_input(&input, &size);
    write_output(input, size);
    switch (size ? input[0] : 0) {
    case 0:
        return 0;
    case 1:
        return 1;
    case 2:
        return 256;
    case 3:
        abort();
    case 4:
        assert(size == 0);
    }
    return 0;
}
