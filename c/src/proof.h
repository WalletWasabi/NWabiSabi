/* Zero-knowledge proof system for WabiSabi.
 * Implements Sigma protocols for linear relations over the secp256k1 group.
 * Matches ProofSystem.cs, Statement.cs, Equation.cs, Knowledge.cs.
 *
 * SPARSE REPRESENTATION:
 * Instead of storing a dense EQUATIONS × WITNESSES generator matrix,
 * we store only the non-zero entries. Each equation has at most
 * MAX_SPARSE_ENTRIES non-zero generators.
 */
#pragma once
#include "mac.h"
#include "transcript.h"
#include "wabisabi_types.h"

/* Maximum dimensions for proof structures.
 * Range proof with width W needs 2W+1 equations and 3W+1 witnesses.
 * With WABISABI_MAX_RANGE_WIDTH=51: 103 equations, 154 witnesses.
 * Using 128/192 for headroom.
 */
#define PROOF_MAX_EQUATIONS 128
#define PROOF_MAX_WITNESSES 192

/* Maximum non-zero generators per equation.
 * Analysis of all proof types:
 *   - IssuerParams: 5 witnesses, all may be used → 5
 *   - ShowCredential: 5 witnesses per equation → 5
 *   - BalanceProof: 2 witnesses → 2
 *   - ZeroProof: 1 witness → 1
 *   - RangeProof equation 0: 1 + W entries (r + all r_i)
 *   - RangeProof bit equations: 2 entries each
 * For W=51: equation 0 needs 52 entries. Use 64 for headroom.
 */
#define MAX_SPARSE_ENTRIES 64

/* ---- Sparse equation representation ---- */

/* A sparse entry: (witness_index, generator) */
typedef struct {
    int witness_idx;        /* Which witness this generator multiplies */
    wabisabi_ge_t generator; /* The generator point */
} wabisabi_sparse_entry_t;

/* A single equation in sparse form: P = sum(w[idx_i] * G_i)
 *   public_point: the known point P
 *   entries[]: sparse (index, generator) pairs
 *   n_entries: number of non-zero entries
 */
typedef struct {
    wabisabi_ge_t public_point;
    wabisabi_sparse_entry_t entries[MAX_SPARSE_ENTRIES];
    int n_entries;
} wabisabi_equation_t;

/* A statement: a list of equations sharing the same witness vector */
typedef struct {
    wabisabi_equation_t equations[PROOF_MAX_EQUATIONS];
    int n_equations;
    int n_witnesses; /* Total witness count (for iteration) */
} wabisabi_statement_t;

/* A proof: public nonces (one per equation) + responses (one per witness) */
typedef struct {
    wabisabi_ge_t public_nonces[PROOF_MAX_EQUATIONS];
    wabisabi_scalar_t responses[PROOF_MAX_WITNESSES];
    int n_nonces;
    int n_responses;
} wabisabi_proof_t;

/* A knowledge pair: statement + witness */
typedef struct {
    wabisabi_statement_t statement;
    wabisabi_scalar_t witness[PROOF_MAX_WITNESSES];
} wabisabi_knowledge_t;

/* ---- Prove / Verify ---- */

/* Prove a list of knowledge items. Writes proofs into out[n].
 * Uses the transcript for Fiat-Shamir and synthetic nonces.
 * random_bytes/rnd_len: extra randomness for nonce generation.
 */
void wabisabi_prove(wabisabi_proof_t* out, wabisabi_transcript_t* transcript, const wabisabi_knowledge_t* knowledge,
                    int n, const uint8_t* random_bytes, size_t rnd_len);

/* Verify a list of statements against proofs. Returns 1 if all valid. */
int wabisabi_verify(wabisabi_transcript_t* transcript, const wabisabi_statement_t* statements, int n_stmt,
                    const wabisabi_proof_t* proofs, int n_proof);

/* ---- High-level statement constructors ---- */

/* IssuerParametersKnowledge: prove MAC was computed with correct key */
void wabisabi_issuer_params_knowledge(wabisabi_knowledge_t* out, const wabisabi_mac_t* mac, const wabisabi_ge_t* ma,
                                      const wabisabi_sk_t* sk);

wabisabi_statement_t wabisabi_issuer_params_statement(const wabisabi_iparams_t* iparams, const wabisabi_mac_t* mac,
                                                      const wabisabi_ge_t* ma);

/* ShowCredentialKnowledge: prove knowledge of a valid credential */
/* Returns the presentation (Ca, Cx0, Cx1, CV, S) via separate fields */
typedef struct {
    wabisabi_ge_t ca, cx0, cx1, cv, s;
} wabisabi_presentation_t;

wabisabi_presentation_t wabisabi_credential_present(const wabisabi_mac_t* mac, int64_t value,
                                                    const wabisabi_scalar_t* randomness, const wabisabi_scalar_t* z);

wabisabi_knowledge_t wabisabi_show_credential_knowledge(const wabisabi_presentation_t* p, const wabisabi_scalar_t* z,
                                                        const wabisabi_mac_t* mac, int64_t value,
                                                        const wabisabi_scalar_t* randomness,
                                                        const wabisabi_iparams_t* iparams);

wabisabi_statement_t wabisabi_show_credential_statement(const wabisabi_presentation_t* p,
                                                        const wabisabi_ge_t* z_point, /* z * iparams.I */
                                                        const wabisabi_iparams_t* iparams);

/* BalanceProofKnowledge */
wabisabi_knowledge_t wabisabi_balance_proof_knowledge(const wabisabi_scalar_t* z_sum,
                                                      const wabisabi_scalar_t* r_delta_sum);

wabisabi_statement_t wabisabi_balance_proof_statement(const wabisabi_ge_t* balance_commitment);

/* ZeroProofKnowledge (bootstrap — proof that Ma = 0*Gg + r*Gh) */
wabisabi_knowledge_t wabisabi_zero_proof_knowledge(const wabisabi_ge_t* ma, const wabisabi_scalar_t* r);

wabisabi_statement_t wabisabi_zero_proof_statement(const wabisabi_ge_t* ma);

/* RangeProofKnowledge: prove amount is in range [0, 2^width) */
typedef struct {
    wabisabi_knowledge_t knowledge;
    wabisabi_ge_t bit_commitments[WABISABI_MAX_RANGE_WIDTH];
    int width;
} wabisabi_range_proof_t;

wabisabi_range_proof_t wabisabi_range_proof_knowledge(const wabisabi_scalar_t* amount,
                                                      const wabisabi_scalar_t* randomness, int width,
                                                      const uint8_t* random_bytes,
                                                      size_t rnd_len); /* for bit randomness */

wabisabi_statement_t wabisabi_range_proof_statement(const wabisabi_ge_t* ma, const wabisabi_ge_t* bit_commitments,
                                                    int width);

/* Pedersen commitment: ma = amount*Gg + randomness*Gh */
void wabisabi_pedersen_commit(wabisabi_ge_t* out, const wabisabi_scalar_t* amount, const wabisabi_scalar_t* randomness);

/* ---- Helper for sparse equation construction ---- */

/* Add a sparse entry to an equation */
static inline void
equation_add_entry(wabisabi_equation_t* eq, int witness_idx, const wabisabi_ge_t* gen) {
    if (eq->n_entries < MAX_SPARSE_ENTRIES) {
        eq->entries[eq->n_entries].witness_idx = witness_idx;
        eq->entries[eq->n_entries].generator = *gen;
        eq->n_entries++;
    }
}
