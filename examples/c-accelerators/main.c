/* A freestanding C guest, linked only against libpico_zkvm.a and pico.ld, that calls every
 * function of zkevm-standards' zkvm_accelerators.h on a known answer. It exits 0, or with the
 * number of the first check that failed. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zkvm_accelerators.h"
#include "vectors.h"

#define CHECK(n, cond)  \
    do {                \
        if (!(cond)) {  \
            return (n); \
        }               \
    } while (0)

static bool eq(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) {
            return false;
        }
    }
    return true;
}

/* `src` copied to `offset` bytes past an 8-byte boundary: byte inputs may start anywhere. */
static _Alignas(8) uint8_t scratch[3][256];

static const uint8_t *at(int slot, size_t offset, const uint8_t *src, size_t n) {
    uint8_t *dst = &scratch[slot][offset];
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
    return dst;
}

typedef zkvm_status (*hash_fn)(const uint8_t *, size_t, zkvm_bytes_32 *);

static int hashes(void) {
    static const struct {
        hash_fn f;
        const uint8_t *data;
        size_t len;
        const uint8_t *out;
    } cases[] = {
        {zkvm_keccak256, keccak256_data, sizeof keccak256_data, keccak256_out},
        {zkvm_sha256, sha256_data, sizeof sha256_data, sha256_out},
        {zkvm_ripemd160, ripemd160_data, sizeof ripemd160_data, ripemd160_out},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        for (size_t offset = 0; offset < 8; offset++) {
            zkvm_bytes_32 out;
            const uint8_t *data = at(0, offset, cases[i].data, cases[i].len);
            CHECK(1 + i, cases[i].f(data, cases[i].len, &out) == ZKVM_EOK);
            CHECK(1 + i, eq(&out, cases[i].out, sizeof out));
        }
    }
    return 0;
}

static int modexp(void) {
    for (size_t offset = 0; offset < 8; offset++) {
        uint8_t out[sizeof modexp_mod];
        const uint8_t *base = at(0, offset, modexp_base, sizeof modexp_base);
        const uint8_t *exp = at(1, offset, modexp_exp, sizeof modexp_exp);
        const uint8_t *mod = at(2, offset, modexp_mod, sizeof modexp_mod);
        CHECK(4, zkvm_modexp(base, sizeof modexp_base, exp, sizeof modexp_exp, mod,
                             sizeof modexp_mod, out) == ZKVM_EOK);
        CHECK(4, eq(out, modexp_out, sizeof out));
    }
    return 0;
}

int main(void) {
    int failed = hashes();
    if (failed) {
        return failed;
    }
    failed = modexp();
    if (failed) {
        return failed;
    }

    zkvm_blake2f_state h;
    for (size_t i = 0; i < sizeof h.data; i++) {
        h.data[i] = blake2f_h[i];
    }
    CHECK(5, zkvm_blake2f(BLAKE2F_ROUNDS, &h, (const zkvm_blake2f_message *)blake2f_m,
                          (const zkvm_blake2f_offset *)blake2f_t, BLAKE2F_F) == ZKVM_EOK);
    CHECK(5, eq(&h, blake2f_out, sizeof h));

    zkvm_secp256k1_pubkey pubkey;
    CHECK(6, zkvm_secp256k1_ecrecover((const zkvm_secp256k1_hash *)secp256k1_ecrecover_msg,
                                      (const zkvm_secp256k1_signature *)secp256k1_ecrecover_sig,
                                      SECP256K1_ECRECOVER_RECID, &pubkey) == ZKVM_EOK);
    CHECK(6, eq(&pubkey, secp256k1_ecrecover_out, sizeof pubkey));

    bool verified = false;
    CHECK(7, zkvm_secp256k1_verify((const zkvm_secp256k1_hash *)secp256k1_verify_msg,
                                   (const zkvm_secp256k1_signature *)secp256k1_verify_sig,
                                   (const zkvm_secp256k1_pubkey *)secp256k1_verify_pubkey,
                                   &verified) == ZKVM_EOK && verified);
    verified = false;
    CHECK(8, zkvm_secp256r1_verify((const zkvm_secp256r1_hash *)secp256r1_verify_msg,
                                   (const zkvm_secp256r1_signature *)secp256r1_verify_sig,
                                   (const zkvm_secp256r1_pubkey *)secp256r1_verify_pubkey,
                                   &verified) == ZKVM_EOK && verified);

    zkvm_bn254_g1_point bn;
    CHECK(9, zkvm_bn254_g1_add((const zkvm_bn254_g1_point *)bn254_g1_add_p1,
                               (const zkvm_bn254_g1_point *)bn254_g1_add_p2, &bn) == ZKVM_EOK);
    CHECK(9, eq(&bn, bn254_g1_add_out, sizeof bn));
    CHECK(10, zkvm_bn254_g1_mul((const zkvm_bn254_g1_point *)bn254_g1_mul_point,
                                (const zkvm_bn254_scalar *)bn254_g1_mul_scalar, &bn) == ZKVM_EOK);
    CHECK(10, eq(&bn, bn254_g1_mul_out, sizeof bn));
    verified = false;
    CHECK(11, zkvm_bn254_pairing((const zkvm_bn254_pairing_pair *)bn254_pairing_pairs,
                                 sizeof bn254_pairing_pairs / sizeof(zkvm_bn254_pairing_pair),
                                 &verified) == ZKVM_EOK && verified);

    verified = false;
    CHECK(12, zkvm_kzg_point_eval((const zkvm_kzg_commitment *)kzg_point_eval_commitment,
                                  (const zkvm_kzg_field_element *)kzg_point_eval_z,
                                  (const zkvm_kzg_field_element *)kzg_point_eval_y,
                                  (const zkvm_kzg_proof *)kzg_point_eval_proof,
                                  &verified) == ZKVM_EOK && verified);

    zkvm_bls12_381_g1_point g1;
    zkvm_bls12_381_g2_point g2;
    CHECK(13, zkvm_bls12_g1_add((const zkvm_bls12_381_g1_point *)bls12_g1_add_p1,
                                (const zkvm_bls12_381_g1_point *)bls12_g1_add_p2, &g1) == ZKVM_EOK);
    CHECK(13, eq(&g1, bls12_g1_add_out, sizeof g1));
    CHECK(14, zkvm_bls12_g1_msm((const zkvm_bls12_381_g1_msm_pair *)bls12_g1_msm_pairs,
                                sizeof bls12_g1_msm_pairs / sizeof(zkvm_bls12_381_g1_msm_pair),
                                &g1) == ZKVM_EOK);
    CHECK(14, eq(&g1, bls12_g1_msm_out, sizeof g1));
    CHECK(15, zkvm_bls12_g2_add((const zkvm_bls12_381_g2_point *)bls12_g2_add_p1,
                                (const zkvm_bls12_381_g2_point *)bls12_g2_add_p2, &g2) == ZKVM_EOK);
    CHECK(15, eq(&g2, bls12_g2_add_out, sizeof g2));
    CHECK(16, zkvm_bls12_g2_msm((const zkvm_bls12_381_g2_msm_pair *)bls12_g2_msm_pairs,
                                sizeof bls12_g2_msm_pairs / sizeof(zkvm_bls12_381_g2_msm_pair),
                                &g2) == ZKVM_EOK);
    CHECK(16, eq(&g2, bls12_g2_msm_out, sizeof g2));
    verified = false;
    CHECK(17, zkvm_bls12_pairing((const zkvm_bls12_381_pairing_pair *)bls12_pairing_pairs,
                                 sizeof bls12_pairing_pairs / sizeof(zkvm_bls12_381_pairing_pair),
                                 &verified) == ZKVM_EOK && verified);
    CHECK(18, zkvm_bls12_map_fp_to_g1((const zkvm_bls12_381_fp *)bls12_map_fp_to_g1_fp,
                                      &g1) == ZKVM_EOK);
    CHECK(18, eq(&g1, bls12_map_fp_to_g1_out, sizeof g1));
    CHECK(19, zkvm_bls12_map_fp2_to_g2((const zkvm_bls12_381_fp2 *)bls12_map_fp2_to_g2_fp,
                                       &g2) == ZKVM_EOK);
    CHECK(19, eq(&g2, bls12_map_fp2_to_g2_out, sizeof g2));
    return 0;
}
