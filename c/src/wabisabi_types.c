/* Core scalar and group element operations using secp256k1 public API */
#include "wabisabi_types.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

secp256k1_context* WABISABI_CTX = NULL;

void
wabisabi_ctx_init(void) {
    if (!WABISABI_CTX) {
        WABISABI_CTX = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        assert(WABISABI_CTX != NULL);
    }
}

void
wabisabi_ctx_cleanup(void) {
    if (WABISABI_CTX) {
        secp256k1_context_destroy(WABISABI_CTX);
        WABISABI_CTX = NULL;
    }
}

/* -------- Scalar operations ----------
 * We use secp256k1's public "seckey" tweak functions.
 * They expect non-zero inputs, so zero is handled specially.
 */

int
wabisabi_scalar_add(wabisabi_scalar_t* r, const wabisabi_scalar_t* a, const wabisabi_scalar_t* b) {
    if (wabisabi_scalar_is_zero(a)) {
        *r = *b;
        return 1;
    }
    if (wabisabi_scalar_is_zero(b)) {
        *r = *a;
        return 1;
    }

    wabisabi_scalar_t tmp = *a;
    int ret = secp256k1_ec_seckey_tweak_add(WABISABI_CTX, tmp.data, b->data);
    if (!ret) {
        /* Result was 0 (a + b = n, which wraps to 0) */
        memset(r->data, 0, WABISABI_SCALAR_SIZE);
        return 1;
    }
    *r = tmp;
    return 1;
}

int
wabisabi_scalar_mul(wabisabi_scalar_t* r, const wabisabi_scalar_t* a, const wabisabi_scalar_t* b) {
    if (wabisabi_scalar_is_zero(a) || wabisabi_scalar_is_zero(b)) {
        memset(r->data, 0, WABISABI_SCALAR_SIZE);
        return 1;
    }
    wabisabi_scalar_t tmp = *a;
    int ret = secp256k1_ec_seckey_tweak_mul(WABISABI_CTX, tmp.data, b->data);
    if (!ret) {
        memset(r->data, 0, WABISABI_SCALAR_SIZE);
        return 1;
    }
    *r = tmp;
    return 1;
}

int
wabisabi_scalar_negate(wabisabi_scalar_t* r, const wabisabi_scalar_t* a) {
    if (wabisabi_scalar_is_zero(a)) {
        memset(r->data, 0, WABISABI_SCALAR_SIZE);
        return 1;
    }
    wabisabi_scalar_t tmp = *a;
    int neg_ok = secp256k1_ec_seckey_negate(WABISABI_CTX, tmp.data);
    (void)neg_ok;
    *r = tmp;
    return 1;
}

int
wabisabi_scalar_get_bit(const wabisabi_scalar_t* s, int i) {
    /* Scalars are big-endian; bit 0 is the LSB at byte 31 */
    int byte_idx = 31 - (i / 8);
    int bit_idx = i % 8;
    return (s->data[byte_idx] >> bit_idx) & 1;
}

/* -------- Group element operations ---------- */

void
wabisabi_ge_add(wabisabi_ge_t* r, const wabisabi_ge_t* a, const wabisabi_ge_t* b) {
    if (a->is_infinity) {
        *r = *b;
        return;
    }
    if (b->is_infinity) {
        *r = *a;
        return;
    }

    const secp256k1_pubkey* ins[2] = {&a->pk, &b->pk};
    secp256k1_pubkey out;
    if (!secp256k1_ec_pubkey_combine(WABISABI_CTX, &out, ins, 2)) {
        /* a + b = infinity (negation pair) */
        r->is_infinity = 1;
        memset(&r->pk, 0, sizeof(r->pk));
        return;
    }
    r->pk = out;
    r->is_infinity = 0;
}

void
wabisabi_ge_negate(wabisabi_ge_t* r, const wabisabi_ge_t* a) {
    if (a->is_infinity) {
        r->is_infinity = 1;
        memset(&r->pk, 0, sizeof(r->pk));
        return;
    }
    *r = *a;
    int neg_ok = secp256k1_ec_pubkey_negate(WABISABI_CTX, &r->pk);
    (void)neg_ok;
}

void
wabisabi_ge_mul(wabisabi_ge_t* r, const wabisabi_scalar_t* s, const wabisabi_ge_t* p) {
    if (wabisabi_scalar_is_zero(s) || p->is_infinity) {
        r->is_infinity = 1;
        memset(&r->pk, 0, sizeof(r->pk));
        return;
    }
    *r = *p;
    r->is_infinity = 0;
    if (!secp256k1_ec_pubkey_tweak_mul(WABISABI_CTX, &r->pk, s->data)) {
        r->is_infinity = 1;
        memset(&r->pk, 0, sizeof(r->pk));
    }
}

void
wabisabi_ge_mul_base(wabisabi_ge_t* r, const wabisabi_scalar_t* s) {
    if (wabisabi_scalar_is_zero(s)) {
        r->is_infinity = 1;
        memset(&r->pk, 0, sizeof(r->pk));
        return;
    }
    r->is_infinity = 0;
    if (!secp256k1_ec_pubkey_create(WABISABI_CTX, &r->pk, s->data)) {
        r->is_infinity = 1;
        memset(&r->pk, 0, sizeof(r->pk));
    }
}

void
wabisabi_ge_multiscalar(wabisabi_ge_t* r, const wabisabi_scalar_t* scalars, const wabisabi_ge_t* points, size_t n) {
    wabisabi_ge_t acc = {.is_infinity = 1};
    memset(&acc.pk, 0, sizeof(acc.pk));

    for (size_t i = 0; i < n; i++) {
        if (wabisabi_scalar_is_zero(&scalars[i]) || points[i].is_infinity) {
            continue;
        }
        wabisabi_ge_t term;
        wabisabi_ge_mul(&term, &scalars[i], &points[i]);
        if (!term.is_infinity) {
            wabisabi_ge_add(&acc, &acc, &term);
        }
    }
    *r = acc;
}

int
wabisabi_ge_equal(const wabisabi_ge_t* a, const wabisabi_ge_t* b) {
    if (a->is_infinity && b->is_infinity) {
        return 1;
    }
    if (a->is_infinity || b->is_infinity) {
        return 0;
    }

    uint8_t sa[WABISABI_GE_SIZE], sb[WABISABI_GE_SIZE];
    size_t sza = WABISABI_GE_SIZE, szb = WABISABI_GE_SIZE;
    secp256k1_ec_pubkey_serialize(WABISABI_CTX, sa, &sza, &a->pk, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(WABISABI_CTX, sb, &szb, &b->pk, SECP256K1_EC_COMPRESSED);
    return memcmp(sa, sb, WABISABI_GE_SIZE) == 0;
}

void
wabisabi_ge_serialize(uint8_t out[WABISABI_GE_SIZE], const wabisabi_ge_t* p) {
    if (p->is_infinity) {
        memset(out, 0, WABISABI_GE_SIZE);
        return;
    }
    size_t sz = WABISABI_GE_SIZE;
    secp256k1_ec_pubkey_serialize(WABISABI_CTX, out, &sz, &p->pk, SECP256K1_EC_COMPRESSED);
}

int
wabisabi_ge_parse(wabisabi_ge_t* p, const uint8_t in[WABISABI_GE_SIZE]) {
    if (in[0] == 0) {
        /* Infinity encoding */
        p->is_infinity = 1;
        memset(&p->pk, 0, sizeof(p->pk));
        return 1;
    }
    p->is_infinity = 0;
    return secp256k1_ec_pubkey_parse(WABISABI_CTX, &p->pk, in, WABISABI_GE_SIZE);
}
