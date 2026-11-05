#include <stdint.h>
// The inverse in KoalaBear's quintic extension F_p[X]/(X^5 + X^2 - 1): five coefficients in, lowest
// first, and five out. Zero gives zero.
void koalabearquinticinv(const uint32_t *in, uint32_t *out);
uint32_t koalabearinv(uint32_t a);
