#include "sha256.h"
#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void
sha256_transform(sha256_t* s, const uint8_t* block) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) | ((uint32_t)block[4 * i + 2] << 8)
               | block[4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(W[i - 15], 7) ^ ROR32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = ROR32(W[i - 2], 17) ^ ROR32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    a = s->state[0];
    b = s->state[1];
    c = s->state[2];
    d = s->state[3];
    e = s->state[4];
    f = s->state[5];
    g = s->state[6];
    h = s->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        T1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        T2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    s->state[0] += a;
    s->state[1] += b;
    s->state[2] += c;
    s->state[3] += d;
    s->state[4] += e;
    s->state[5] += f;
    s->state[6] += g;
    s->state[7] += h;
}

void
sha256_init(sha256_t* s) {
    s->state[0] = 0x6a09e667;
    s->state[1] = 0xbb67ae85;
    s->state[2] = 0x3c6ef372;
    s->state[3] = 0xa54ff53a;
    s->state[4] = 0x510e527f;
    s->state[5] = 0x9b05688c;
    s->state[6] = 0x1f83d9ab;
    s->state[7] = 0x5be0cd19;
    s->bytes = 0;
}

void
sha256_update(sha256_t* s, const uint8_t* data, size_t len) {
    size_t off = (size_t)(s->bytes & 63);
    s->bytes += len;
    while (len > 0) {
        size_t n = 64 - off;
        if (n > len) {
            n = len;
        }
        memcpy(s->buf + off, data, n);
        off += n;
        data += n;
        len -= n;
        if (off == 64) {
            sha256_transform(s, s->buf);
            off = 0;
        }
    }
}

void
sha256_final(sha256_t* s, uint8_t out[32]) {
    uint64_t bits = s->bytes * 8;
    size_t off = (size_t)(s->bytes & 63);
    s->buf[off++] = 0x80;
    if (off > 56) {
        memset(s->buf + off, 0, 64 - off);
        sha256_transform(s, s->buf);
        off = 0;
    }
    memset(s->buf + off, 0, 56 - off);
    for (int i = 7; i >= 0; i--) {
        s->buf[56 + (7 - i)] = (uint8_t)(bits >> (8 * i));
    }
    sha256_transform(s, s->buf);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)(s->state[i]);
    }
}

void
sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    sha256_t s;
    sha256_init(&s);
    sha256_update(&s, data, len);
    sha256_final(&s, out);
}
