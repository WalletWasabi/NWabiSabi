/* Strobe128 — direct port of WabiSabi/Crypto/StrobeProtocol/Strobe.cs */
#include "strobe.h"
#include <assert.h>
#include <string.h>

#define DDATA 0x04
#define DRATE 0x80

/* ------------- Keccak-f1600 ------------- */
/* Exact port of the C# KeccakF1600 function */

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL,
    0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void
keccak_f1600(uint8_t state[200]) {
    uint64_t* S = (uint64_t*)state;
    uint64_t a00 = S[0], a01 = S[1], a02 = S[2], a03 = S[3], a04 = S[4];
    uint64_t a05 = S[5], a06 = S[6], a07 = S[7], a08 = S[8], a09 = S[9];
    uint64_t a10 = S[10], a11 = S[11], a12 = S[12], a13 = S[13], a14 = S[14];
    uint64_t a15 = S[15], a16 = S[16], a17 = S[17], a18 = S[18], a19 = S[19];
    uint64_t a20 = S[20], a21 = S[21], a22 = S[22], a23 = S[23], a24 = S[24];

    for (int i = 0; i < 24; i++) {
        /* theta */
        uint64_t c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
        uint64_t c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
        uint64_t c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
        uint64_t c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
        uint64_t c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

        uint64_t d1 = ROL64(c1, 1) ^ c4;
        uint64_t d2 = ROL64(c2, 1) ^ c0;
        uint64_t d3 = ROL64(c3, 1) ^ c1;
        uint64_t d4 = ROL64(c4, 1) ^ c2;
        uint64_t d0 = ROL64(c0, 1) ^ c3;

        a00 ^= d1;
        a05 ^= d1;
        a10 ^= d1;
        a15 ^= d1;
        a20 ^= d1;
        a01 ^= d2;
        a06 ^= d2;
        a11 ^= d2;
        a16 ^= d2;
        a21 ^= d2;
        a02 ^= d3;
        a07 ^= d3;
        a12 ^= d3;
        a17 ^= d3;
        a22 ^= d3;
        a03 ^= d4;
        a08 ^= d4;
        a13 ^= d4;
        a18 ^= d4;
        a23 ^= d4;
        a04 ^= d0;
        a09 ^= d0;
        a14 ^= d0;
        a19 ^= d0;
        a24 ^= d0;

        /* rho/pi */
        uint64_t t;
        t = ROL64(a01, 1);
        a01 = ROL64(a06, 44);
        a06 = ROL64(a09, 20);
        a09 = ROL64(a22, 61);
        a22 = ROL64(a14, 39);
        a14 = ROL64(a20, 18);
        a20 = ROL64(a02, 62);
        a02 = ROL64(a12, 43);
        a12 = ROL64(a13, 25);
        a13 = ROL64(a19, 8);
        a19 = ROL64(a23, 56);
        a23 = ROL64(a15, 41);
        a15 = ROL64(a04, 27);
        a04 = ROL64(a24, 14);
        a24 = ROL64(a21, 2);
        a21 = ROL64(a08, 55);
        a08 = ROL64(a16, 45);
        a16 = ROL64(a05, 36);
        a05 = ROL64(a03, 28);
        a03 = ROL64(a18, 21);
        a18 = ROL64(a17, 15);
        a17 = ROL64(a11, 10);
        a11 = ROL64(a07, 6);
        a07 = ROL64(a10, 3);
        a10 = t;

        /* chi — must use original values for all 5 terms (parallel operation).
     * Save x0 and x1 before modifying them, so x4 = x4^(~old_x0 & old_x1). */
        uint64_t tmp, tmp1;
#define CHI5(x0, x1, x2, x3, x4)                                                                                       \
    tmp = x0;                                                                                                          \
    tmp1 = x1;                                                                                                         \
    x0 ^= (~x1 & x2);                                                                                                  \
    x1 ^= (~x2 & x3);                                                                                                  \
    x2 ^= (~x3 & x4);                                                                                                  \
    x3 ^= (~x4 & tmp);                                                                                                 \
    x4 ^= (~tmp & tmp1);
        CHI5(a00, a01, a02, a03, a04)
        CHI5(a05, a06, a07, a08, a09)
        CHI5(a10, a11, a12, a13, a14)
        CHI5(a15, a16, a17, a18, a19)
        CHI5(a20, a21, a22, a23, a24)
#undef CHI5

        /* iota */
        a00 ^= KECCAK_RC[i];
    }

    S[0] = a00;
    S[1] = a01;
    S[2] = a02;
    S[3] = a03;
    S[4] = a04;
    S[5] = a05;
    S[6] = a06;
    S[7] = a07;
    S[8] = a08;
    S[9] = a09;
    S[10] = a10;
    S[11] = a11;
    S[12] = a12;
    S[13] = a13;
    S[14] = a14;
    S[15] = a15;
    S[16] = a16;
    S[17] = a17;
    S[18] = a18;
    S[19] = a19;
    S[20] = a20;
    S[21] = a21;
    S[22] = a22;
    S[23] = a23;
    S[24] = a24;
}

/* ------------- Strobe internals ------------- */

static void
strobe_run_f(strobe128_t* s) {
    s->state[s->pos] ^= s->pos_begin;
    s->state[s->pos + 1] ^= DDATA;
    s->state[STROBE_RATE + 1] ^= DRATE;
    keccak_f1600(s->state);
    s->pos = 0;
    s->pos_begin = 0;
}

static void
strobe_absorb(strobe128_t* s, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        s->state[s->pos++] ^= data[i];
        if (s->pos == STROBE_RATE) {
            strobe_run_f(s);
        }
    }
}

static void
strobe_squeeze(strobe128_t* s, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = s->state[s->pos];
        s->state[s->pos++] = 0;
        if (s->pos == STROBE_RATE) {
            strobe_run_f(s);
        }
    }
}

static void
strobe_override(strobe128_t* s, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        s->state[s->pos++] = data[i];
        if (s->pos == STROBE_RATE) {
            strobe_run_f(s);
        }
    }
}

static void
strobe_begin_op(strobe128_t* s, uint8_t flags, int more) {
    if (more) {
        assert(flags == s->cur_flags);
        return;
    }
    assert(!(s->cur_flags & STROBE_FLAG_T)); /* transport not implemented */
    uint8_t old_begin = s->pos_begin;
    s->cur_flags = flags;
    s->pos_begin = (uint8_t)(s->pos + 1);

    uint8_t ab[2] = {old_begin, flags};
    strobe_absorb(s, ab, 2);

    int force_f = (flags & STROBE_FLAG_C) || (flags & STROBE_FLAG_K);
    if (force_f && s->pos != 0) {
        strobe_run_f(s);
    }
}

/* ------------- Public API ------------- */

void
strobe128_init(strobe128_t* s, const char* protocol) {
    /* Initial state: [1, r/8, 1, 0, 1, 12*8] ++ "STROBEv1.0.2" */
    memset(s->state, 0, sizeof(s->state));
    s->pos = 0;
    s->pos_begin = 0;
    s->cur_flags = 0;

    static const uint8_t STROBE_HEADER[] = {1, STROBE_RATE + 2, 1, 0, 1, 96}; /* 12*8=96 */
    static const uint8_t STROBE_ID[] = "STROBEv1.0.2";

    memcpy(s->state, STROBE_HEADER, sizeof(STROBE_HEADER));
    memcpy(s->state + sizeof(STROBE_HEADER), STROBE_ID, sizeof(STROBE_ID) - 1);
    keccak_f1600(s->state);

    size_t plen = strlen(protocol);
    strobe128_meta_ad(s, (const uint8_t*)protocol, plen, 0);
}

void
strobe128_clone(strobe128_t* dst, const strobe128_t* src) {
    memcpy(dst, src, sizeof(strobe128_t));
}

void
strobe128_meta_ad(strobe128_t* s, const uint8_t* data, size_t len, int more) {
    strobe_begin_op(s, STROBE_FLAG_M | STROBE_FLAG_A, more);
    strobe_absorb(s, data, len);
}

void
strobe128_ad(strobe128_t* s, const uint8_t* data, size_t len, int more) {
    strobe_begin_op(s, STROBE_FLAG_A, more);
    strobe_absorb(s, data, len);
}

void
strobe128_prf(strobe128_t* s, uint8_t* out, size_t len, int more) {
    strobe_begin_op(s, STROBE_FLAG_I | STROBE_FLAG_A | STROBE_FLAG_C, more);
    strobe_squeeze(s, out, len);
}

void
strobe128_key(strobe128_t* s, const uint8_t* data, size_t len, int more) {
    strobe_begin_op(s, STROBE_FLAG_A | STROBE_FLAG_C, more);
    strobe_override(s, data, len);
}
