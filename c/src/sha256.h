/* SHA-256 implementation for WabiSabi hash-to-curve.
 * Based on the FIPS 180-4 specification.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint8_t buf[64];
    uint64_t bytes;
} sha256_t;

void sha256_init(sha256_t* s);
void sha256_update(sha256_t* s, const uint8_t* data, size_t len);
void sha256_final(sha256_t* s, uint8_t out[32]);

/* One-shot: hash data into out[32] */
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
