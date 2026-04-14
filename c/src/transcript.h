/* Proof transcript — high-level Strobe-based Fiat-Shamir transform.
 * Matches WabiSabi/Crypto/ZeroKnowledge/Transcript.cs.
 */
#pragma once
#include "strobe.h"
#include "wabisabi_types.h"

/* A proof transcript tracks the hash state of a compound Sigma protocol */
typedef struct {
    strobe128_t strobe;
} wabisabi_transcript_t;

/* Initialize transcript with a domain-separator label.
 * label is a UTF-8 byte sequence of length label_len.
 */
void wabisabi_transcript_init(wabisabi_transcript_t* t, const uint8_t* label, size_t label_len);

/* Clone transcript state (for synthetic nonce generation) */
void wabisabi_transcript_clone(wabisabi_transcript_t* dst, const wabisabi_transcript_t* src);

/* Commit a statement: absorbs public points and generators */
void wabisabi_transcript_commit_statement(wabisabi_transcript_t* t, const wabisabi_ge_t* public_points, size_t n_public,
                                          const wabisabi_ge_t* generators, size_t n_gen);

/* Commit public nonces (R values) */
void wabisabi_transcript_commit_nonces(wabisabi_transcript_t* t, const wabisabi_ge_t* nonces, size_t n);

/* Generate Fiat-Shamir challenge (loops until no overflow) */
void wabisabi_transcript_challenge(wabisabi_scalar_t* out, wabisabi_transcript_t* t);

/* Synthetic nonce provider — builds on a cloned transcript */
typedef struct {
    strobe128_t strobe;
    int n_secrets;
} wabisabi_nonce_provider_t;

void wabisabi_nonce_provider_init(wabisabi_nonce_provider_t* p, const wabisabi_transcript_t* t,
                                  const wabisabi_scalar_t* secrets, int n, const uint8_t* extra_random, size_t rnd_len);

void wabisabi_nonce_provider_next(wabisabi_scalar_t* out, wabisabi_nonce_provider_t* p);

/* Fill a scalar array from the provider */
void wabisabi_nonce_provider_fill(wabisabi_scalar_t* out, int n, wabisabi_nonce_provider_t* p);
