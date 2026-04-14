/* Strobe128 duplex sponge based on Keccak-f1600.
 * Implements the Merlin transcript framework for Sigma protocol proofs.
 * Matches the C# Strobe.cs implementation exactly.
 * Reference: https://strobe.sourceforge.io/papers/strobe-20170130.pdf
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define STROBE_RATE   166 /* r/8 - 2 where r = 1360 bits rate */

/* Strobe operation flags */
#define STROBE_FLAG_I 0x01
#define STROBE_FLAG_A 0x02
#define STROBE_FLAG_C 0x04
#define STROBE_FLAG_T 0x08
#define STROBE_FLAG_M 0x10
#define STROBE_FLAG_K 0x20

typedef struct {
    uint8_t state[200]; /* Keccak-f1600 state: 25 x 8 bytes */
    uint8_t pos;
    uint8_t pos_begin;
    uint8_t cur_flags;
} strobe128_t;

/* Initialize with protocol identifier (domain separator) */
void strobe128_init(strobe128_t* s, const char* protocol);

/* Copy state */
void strobe128_clone(strobe128_t* dst, const strobe128_t* src);

/* AD with metadata: meta-AD(data) */
void strobe128_meta_ad(strobe128_t* s, const uint8_t* data, size_t len, int more);

/* AD: AD(data) */
void strobe128_ad(strobe128_t* s, const uint8_t* data, size_t len, int more);

/* PRF: squeeze len bytes into out */
void strobe128_prf(strobe128_t* s, uint8_t* out, size_t len, int more);

/* KEY: key(data) */
void strobe128_key(strobe128_t* s, const uint8_t* data, size_t len, int more);
