/* Seed-expansion randomness stream for the client/issuer.
 *
 * Instead of carrying a full randomness buffer across the FFI, the native side
 * receives a single 32-byte seed and expands it deterministically into a
 * sequence of 32-byte blocks
 *
 *     block_i = SHA256(seed || LE32(i)),   i = 0, 1, 2, ...
 *
 * Both implementations expand the *same* seed with the *same* block function and
 * consume the blocks in the *same* order, so for an identical seed they emit
 * byte-identical wire output for the same logical input (a differential-testing
 * seam — see the interop byte-equality tests). The managed side mirrors this
 * block function with Sha256SeedRandom.
 *
 *   - scalar()  mirrors WasabiRandom.GetScalar(): take the next block, reject on
 *               overflow OR zero (secp256k1_ec_seckey_verify accepts iff in [1,n)),
 *               advancing to the next block until valid.
 *   - bytes(n)  mirrors a raw random.GetBytes(n) fed as STROBE key material: copy
 *               the next n bytes taken from whole 32-byte blocks (no rejection).
 *               n must be a multiple of 32 — every draw in the protocol is exactly
 *               one 32-byte block.
 *
 * The stream never exhausts (the seed expands indefinitely), so bytes()/scalar()
 * always succeed and return 1; the int return is kept for signature parity with
 * the buffer-backed variant so the reconciled callers stay unchanged.
 */
#pragma once
#include "wabisabi_types.h"
#include "sha256.h"
#include <string.h>

typedef struct {
    uint8_t seed[WABISABI_SCALAR_SIZE];
    uint32_t counter;
} wabisabi_rand_stream_t;

static inline void
wabisabi_rand_stream_init(wabisabi_rand_stream_t* s, const uint8_t* seed) {
    memcpy(s->seed, seed, WABISABI_SCALAR_SIZE);
    s->counter = 0;
}

/* Generate the next 32-byte block: SHA256(seed || LE32(counter++)). */
static inline void
wabisabi_rand_stream_block(wabisabi_rand_stream_t* s, uint8_t out[WABISABI_SCALAR_SIZE]) {
    uint8_t preimage[WABISABI_SCALAR_SIZE + 4];
    memcpy(preimage, s->seed, WABISABI_SCALAR_SIZE);
    uint32_t c = s->counter++;
    preimage[WABISABI_SCALAR_SIZE + 0] = (uint8_t)c;
    preimage[WABISABI_SCALAR_SIZE + 1] = (uint8_t)(c >> 8);
    preimage[WABISABI_SCALAR_SIZE + 2] = (uint8_t)(c >> 16);
    preimage[WABISABI_SCALAR_SIZE + 3] = (uint8_t)(c >> 24);
    sha256(preimage, sizeof(preimage), out);
}

/* Copy the next n bytes (n must be a multiple of 32). Always succeeds (returns 1);
 * the int return mirrors the buffer-backed variant so callers stay unchanged. */
static inline int
wabisabi_rand_stream_bytes(wabisabi_rand_stream_t* s, uint8_t* out, size_t n) {
    for (size_t off = 0; off < n; off += WABISABI_SCALAR_SIZE) {
        wabisabi_rand_stream_block(s, out + off);
    }
    return 1;
}

/* Draw the next valid scalar (reject overflow/zero, matching GetScalar). */
static inline int
wabisabi_rand_stream_scalar(wabisabi_rand_stream_t* s, wabisabi_scalar_t* out) {
    for (;;) {
        wabisabi_rand_stream_block(s, out->data);
        if (secp256k1_ec_seckey_verify(WABISABI_CTX, out->data)) {
            return 1;
        }
    }
}
