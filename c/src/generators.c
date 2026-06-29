/* Generator computation — matches C# Generators.cs */
#include "generators.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "field.h"
#include "sha256.h"

wabisabi_ge_t WABISABI_G;
wabisabi_ge_t WABISABI_Gw, WABISABI_Gwp, WABISABI_Gx0, WABISABI_Gx1, WABISABI_GV;
wabisabi_ge_t WABISABI_Gg, WABISABI_Gh, WABISABI_Ga, WABISABI_Gs;
wabisabi_scalar_t WABISABI_POW2[255];
wabisabi_ge_t WABISABI_NEG_GH_POW2[255];

const wabisabi_scalar_t WABISABI_SCALAR_ZERO = {{0}};
const wabisabi_scalar_t WABISABI_SCALAR_ONE = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};

/* The point at infinity (identity element) - is_infinity = 1 */
const wabisabi_ge_t GE_INFINITY = {{.data = {0}}, 1};

/* WABISABI_U: computed per-MAC from t, but we need a placeholder for
 * IssuerParams proofs. The actual U is passed via the MAC struct. */
wabisabi_ge_t WABISABI_U;

void
wabisabi_generator_from_bytes(wabisabi_ge_t* out, const uint8_t* data, size_t len) {
    uint8_t buf[WABISABI_SCALAR_SIZE];
    sha256(data, len, buf);

    while (1) {
        uint8_t compressed[WABISABI_GE_SIZE];
        if (fe_try_xquad(compressed, buf)) {
            if (wabisabi_ge_parse(out, compressed)) {
                return;
            }
        }
        /* Hash again */
        sha256(buf, WABISABI_SCALAR_SIZE, buf);
    }
}

void
wabisabi_generator_from_text(wabisabi_ge_t* out, const char* text) {
    wabisabi_generator_from_bytes(out, (const uint8_t*)text, strlen(text));
}

void
wabisabi_generate_u(wabisabi_ge_t* u, const wabisabi_scalar_t* t) {
    /* MAC.GenerateU: FromBuffer(t.ToBytes()) */
    wabisabi_generator_from_bytes(u, t->data, WABISABI_SCALAR_SIZE);
}

/* Compute 2^i as a scalar (big-endian SCALAR_SIZE bytes) */
static void
scalar_pow2(wabisabi_scalar_t* r, int i) {
    memset(r->data, 0, WABISABI_SCALAR_SIZE);
    int byte_idx = 31 - (i / 8);
    int bit_idx = i % 8;
    r->data[byte_idx] = (uint8_t)(1 << bit_idx);
}

void
wabisabi_generators_init(void) {
    assert(WABISABI_CTX != NULL);

    /* G: standard secp256k1 base point (compressed) */
    static const uint8_t G_COMPRESSED[WABISABI_GE_SIZE] = {
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
    if (!wabisabi_ge_parse(&WABISABI_G, G_COMPRESSED)) {
        abort();
    }

    wabisabi_generator_from_text(&WABISABI_Gw, "Gw");
    wabisabi_generator_from_text(&WABISABI_Gwp, "Gwp");
    wabisabi_generator_from_text(&WABISABI_Gx0, "Gx0");
    wabisabi_generator_from_text(&WABISABI_Gx1, "Gx1");
    wabisabi_generator_from_text(&WABISABI_GV, "GV");
    wabisabi_generator_from_text(&WABISABI_Gg, "Gg");
    wabisabi_generator_from_text(&WABISABI_Gh, "Gh");
    wabisabi_generator_from_text(&WABISABI_Ga, "Ga");
    wabisabi_generator_from_text(&WABISABI_Gs, "Gs");

    /* Powers of two and negated Gh powers */
    for (int i = 0; i < 255; i++) {
        scalar_pow2(&WABISABI_POW2[i], i);

        /* NEG_GH_POW2[i] = -(2^i) * Gh */
        wabisabi_scalar_t neg_pow2;
        wabisabi_scalar_negate(&neg_pow2, &WABISABI_POW2[i]);
        wabisabi_ge_mul(&WABISABI_NEG_GH_POW2[i], &neg_pow2, &WABISABI_Gh);
    }
}
