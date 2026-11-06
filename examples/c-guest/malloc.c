/*
 * A C guest on newlib: malloc, calloc, realloc and free are newlib's, and its heap grows through
 * the runtime's sbrk (build.sh links it when NEWLIB_GCC is set).
 *
 * It reads its input first, which takes heap from the same bump pointer, then allocates around
 * it, and finally echoes the input followed by "malloc ok": an input that comes back whole means
 * newlib's heap and the runtime's never overlapped. Any other exit code names the first check
 * that failed.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void read_input(const uint8_t **buf_ptr, size_t *buf_size);
void write_output(const uint8_t *output, size_t size);

static int all(const unsigned char *p, size_t n, unsigned char v) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != v) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    const uint8_t *input;
    size_t size;
    read_input(&input, &size);

    enum { N = 64 };
    unsigned char *blocks[N];
    size_t sizes[N];
    for (int i = 0; i < N; i++) {
        sizes[i] = (size_t)(i * i * 37 % 5000) + 1;
        blocks[i] = malloc(sizes[i]);
        if (!blocks[i]) {
            return 1;
        }
        memset(blocks[i], i, sizes[i]);
    }
    for (int i = 0; i < N; i++) {
        if (!all(blocks[i], sizes[i], (unsigned char)i)) {
            return 2; /* two blocks overlap */
        }
    }
    for (int i = 0; i < N; i += 2) {
        free(blocks[i]);
    }
    for (int i = 1; i < N; i += 2) {
        unsigned char *grown = realloc(blocks[i], sizes[i] * 3);
        if (!grown) {
            return 3;
        }
        if (!all(grown, sizes[i], (unsigned char)i)) {
            return 4; /* realloc lost the contents */
        }
        blocks[i] = grown;
    }
    unsigned char *big = malloc(1 << 20);
    if (!big) {
        return 5;
    }
    memset(big, 0xa5, 1 << 20);
    if (!all(big, 1 << 20, 0xa5)) {
        return 6;
    }
    unsigned char *zeroed = calloc(1000, 4);
    if (!zeroed || !all(zeroed, 4000, 0)) {
        return 7;
    }

    write_output(input, size);
    write_output((const uint8_t *)"malloc ok", 9);
    return 0;
}
