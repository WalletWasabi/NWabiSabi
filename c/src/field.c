/* Minimal secp256k1 field arithmetic (mod p).
 * p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 * = 2^256 - 2^32 - 977
 */
#include "field.h"
#include <stdint.h>
#include <string.h>

/* p in 64-bit little-endian limbs */
static const uint64_t P[4] = {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                              0xFFFFFFFFFFFFFFFFULL};

/* ----------- helpers ----------- */

static inline int
fe_cmp(const fe_t* a, const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a->n[i] > b[i]) {
            return 1;
        }
        if (a->n[i] < b[i]) {
            return -1;
        }
    }
    return 0;
}

/* Conditionally subtract p if a >= p */
static void
fe_reduce(fe_t* r) {
    if (fe_cmp(r, P) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
            __uint128_t t = (__uint128_t)r->n[i] - P[i] - borrow;
            r->n[i] = (uint64_t)t;
            borrow = (t >> 127) & 1;
        }
    }
}

int
fe_set_b32(fe_t* r, const uint8_t b[32]) {
    for (int i = 0; i < 4; i++) {
        int j = 3 - i;
        r->n[i] = ((uint64_t)b[j * 8 + 0] << 56) | ((uint64_t)b[j * 8 + 1] << 48) | ((uint64_t)b[j * 8 + 2] << 40)
                  | ((uint64_t)b[j * 8 + 3] << 32) | ((uint64_t)b[j * 8 + 4] << 24) | ((uint64_t)b[j * 8 + 5] << 16)
                  | ((uint64_t)b[j * 8 + 6] << 8) | (uint64_t)b[j * 8 + 7];
    }
    if (fe_cmp(r, P) >= 0) {
        return 0; /* out of range */
    }
    return 1;
}

void
fe_get_b32(uint8_t b[32], const fe_t* a) {
    for (int i = 0; i < 4; i++) {
        int j = 3 - i;
        b[j * 8 + 0] = (uint8_t)(a->n[i] >> 56);
        b[j * 8 + 1] = (uint8_t)(a->n[i] >> 48);
        b[j * 8 + 2] = (uint8_t)(a->n[i] >> 40);
        b[j * 8 + 3] = (uint8_t)(a->n[i] >> 32);
        b[j * 8 + 4] = (uint8_t)(a->n[i] >> 24);
        b[j * 8 + 5] = (uint8_t)(a->n[i] >> 16);
        b[j * 8 + 6] = (uint8_t)(a->n[i] >> 8);
        b[j * 8 + 7] = (uint8_t)a->n[i];
    }
}

int
fe_is_odd(const fe_t* a) {
    return a->n[0] & 1;
}

void
fe_add(fe_t* r, const fe_t* a, const fe_t* b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t t = (__uint128_t)a->n[i] + b->n[i] + carry;
        r->n[i] = (uint64_t)t;
        carry = (uint64_t)(t >> 64);
    }
    fe_reduce(r);
}

void
fe_add_int(fe_t* r, const fe_t* a, uint32_t k) {
    fe_t b = {0};
    b.n[0] = k;
    fe_add(r, a, &b);
}

/* Reduce a 512-bit number (8 x uint64 little-endian) mod p.
 * p = 2^256 - 2^32 - 977, so hi * 2^256 ≡ hi * (2^32 + 977) (mod p).
 *
 * Decompose each hi limb's contribution:
 *   v[i+4] * (2^32 + 977) = v[i+4]*977  (at bit 64*i)
 *                          + (v[i+4] & 0xFFFFFFFF) * 2^32  (at bit 64*i+32,
 * within limb i)
 *                          + (v[i+4] >> 32)                (at bit 64*(i+1),
 * into limb i+1)
 */
static void
fe_reduce512(fe_t* r, const uint64_t v[8]) {
    __uint128_t acc[5] = {0};
    for (int i = 0; i < 4; i++) {
        acc[i] = v[i];
    }
    for (int i = 0; i < 4; i++) {
        uint64_t hi = v[i + 4];
        acc[i] += (__uint128_t)hi * 977ULL;
        acc[i] += (__uint128_t)(hi & 0xFFFFFFFFULL) << 32;
        acc[i + 1] += hi >> 32;
    }
    /* Propagate carries */
    for (int i = 0; i < 4; i++) {
        acc[i + 1] += acc[i] >> 64;
        r->n[i] = (uint64_t)acc[i];
    }
    /* acc[4] holds carry past 256 bits — fold it back (acc[4] < 2^33) */
    uint64_t carry = (uint64_t)acc[4];
    if (carry) {
        /* carry * (2^32 + 977) split cleanly: carry < 2^33 so carry*977 < 2^43,
     * carry*2^32 < 2^65 — handle with 128-bit arithmetic */
        __uint128_t extra = (__uint128_t)carry * 977ULL + ((__uint128_t)(carry & 0xFFFFFFFFULL) << 32);
        __uint128_t t = (__uint128_t)r->n[0] + extra;
        r->n[0] = (uint64_t)t;
        t = (__uint128_t)r->n[1] + (carry >> 32) + (t >> 64);
        r->n[1] = (uint64_t)t;
        t = (__uint128_t)r->n[2] + (t >> 64);
        r->n[2] = (uint64_t)t;
        t = (__uint128_t)r->n[3] + (t >> 64);
        r->n[3] = (uint64_t)t;
    }
    fe_reduce(r);
}

void
fe_mul(fe_t* r, const fe_t* a, const fe_t* b) {
    uint64_t v[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            __uint128_t t = (__uint128_t)a->n[i] * b->n[j] + v[i + j] + carry;
            v[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        v[i + 4] += carry;
    }
    fe_reduce512(r, v);
}

void
fe_sqr(fe_t* r, const fe_t* a) {
    fe_mul(r, a, a);
}

/* r = a^e mod p using binary square-and-multiply.
 * e given as 32-byte big-endian.
 */
static void
fe_pow_b32(fe_t* r, const fe_t* a, const uint8_t e[32]) {
    fe_t base = *a;
    fe_t result = {{1, 0, 0, 0}}; /* multiplicative identity */
    for (int i = 0; i < 32; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            fe_sqr(&result, &result);
            if ((e[i] >> bit) & 1) {
                fe_mul(&result, &result, &base);
            }
        }
    }
    *r = result;
}

int
fe_sqrt(fe_t* r, const fe_t* a) {
    /* p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p
   * (p+1)/4 =
   * 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C
   */
    static const uint8_t E[32] = {0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0x0C};

    fe_t y;
    fe_pow_b32(&y, a, E);

    /* Verify y^2 == a */
    fe_t y2;
    fe_sqr(&y2, &y);
    if (memcmp(y2.n, a->n, sizeof(y2.n)) != 0) {
        return 0; /* not a QR */
    }

    *r = y;
    return 1;
}

int
fe_try_xquad(uint8_t r_compressed[33], const uint8_t x[32]) {
    fe_t fx;
    if (!fe_set_b32(&fx, x)) {
        return 0;
    }

    /* y^2 = x^3 + 7 */
    fe_t x2, x3, y2;
    fe_sqr(&x2, &fx);
    fe_mul(&x3, &fx, &x2);
    fe_add_int(&y2, &x3, 7);

    fe_t y;
    if (!fe_sqrt(&y, &y2)) {
        return 0; /* x not on curve */
    }

    /* The "xquad" y is the quadratic residue, which fe_sqrt already gives
   * (it computes a^((p+1)/4) which is the principal sqrt).
   * Set the parity prefix based on whether y is odd.
   */
    r_compressed[0] = fe_is_odd(&y) ? 0x03 : 0x02;
    memcpy(r_compressed + 1, x, 32);
    return 1;
}
