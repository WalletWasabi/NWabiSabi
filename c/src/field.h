/* Minimal secp256k1 field arithmetic (mod p) for hash-to-curve.
 * p = 2^256 - 2^32 - 977
 * Only the operations needed for secp256k1_ge_set_xquad equivalent.
 */
#pragma once
#include <stdint.h>

/* Field element: 4 x uint64_t, little-endian limbs, always reduced mod p */
typedef struct {
    uint64_t n[4];
} fe_t;

/* Parse 32-byte big-endian into fe. Returns 0 if >= p. */
int fe_set_b32(fe_t* r, const uint8_t b[32]);

/* Serialize fe to 32-byte big-endian */
void fe_get_b32(uint8_t b[32], const fe_t* a);

/* Returns 1 if a is odd */
int fe_is_odd(const fe_t* a);

/* r = a + b mod p */
void fe_add(fe_t* r, const fe_t* a, const fe_t* b);

/* r = a * b mod p */
void fe_mul(fe_t* r, const fe_t* a, const fe_t* b);

/* r = a^2 mod p */
void fe_sqr(fe_t* r, const fe_t* a);

/* r = a + k mod p  (k small positive integer) */
void fe_add_int(fe_t* r, const fe_t* a, uint32_t k);

/* r = sqrt(a) mod p  (p ≡ 3 mod 4, so r = a^((p+1)/4) mod p)
 * Returns 1 if a is a quadratic residue, 0 otherwise. */
int fe_sqrt(fe_t* r, const fe_t* a);

/* Try to create a secp256k1 point from x using the "xquad" convention.
 * r_compressed[0] = 0x02 or 0x03, r_compressed[1..32] = x.
 * Matches Generators.FromBuffer / GE.TryCreateXQuad behavior.
 * Returns 1 on success. */
int fe_try_xquad(uint8_t r_compressed[33], const uint8_t x[32]);
