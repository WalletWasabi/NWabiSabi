/* Credential issuer — matches CredentialIssuer.cs */
#include "issuer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "generators.h"
#include "sha256.h"

/* ---- Issuer ---- */

static int
ceil_log2(int64_t v) {
    int w = 0;
    int64_t n = 1;
    while (n < v) {
        n <<= 1;
        w++;
    }
    return w;
}

void
wabisabi_issuer_state_init(wabisabi_issuer_state_t* issuer, const wabisabi_sk_t* sk, int64_t max_amount) {
    issuer->sk = *sk;
    wabisabi_compute_iparams(&issuer->iparams, sk);
    issuer->max_amount = max_amount;
    issuer->range_proof_width = ceil_log2(max_amount);
    issuer->balance = 0;
}

/* Build transcript for the protocol */
static void
build_transcript(wabisabi_transcript_t* t, int is_null) {
    char label[64];
    snprintf(label, sizeof(label), "UnifiedRegistration/%d/%s", WABISABI_CREDENTIAL_COUNT, is_null ? "True" : "False");
    wabisabi_transcript_init(t, (const uint8_t*)label, strlen(label));
}

/* Issue one credential and return MAC + knowledge */
static void
issue_credential(wabisabi_mac_t* mac_out, wabisabi_knowledge_t* kn_out, const wabisabi_issuer_state_t* issuer,
                 const wabisabi_ge_t* ma, const uint8_t* t_bytes) {
    wabisabi_scalar_t t;
    memcpy(t.data, t_bytes, WABISABI_SCALAR_SIZE);
    wabisabi_mac_compute(mac_out, &issuer->sk, ma, &t);
    wabisabi_issuer_params_knowledge(kn_out, mac_out, ma, &issuer->sk);
}

wabisabi_error_t
wabisabi_issuer_state_handle_zero(wabisabi_issuer_state_t* issuer, const wabisabi_zero_request_t* req,
                                  wabisabi_response_t* resp, const uint8_t* random_bytes) {
    /* Verify all requests have 0 bit commitments */
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        if (req->requested[i].n_bit_commitments != 0) {
            return WABISABI_ERR_INVALID_BIT_COMMITMENT;
        }
    }

    /* Build statements: zero proofs for each requested credential */
    wabisabi_statement_t* statements = malloc(WABISABI_CREDENTIAL_COUNT * sizeof(wabisabi_statement_t));
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        wabisabi_zero_proof_statement_into(&statements[i], &req->requested[i].ma);
    }

    wabisabi_transcript_t transcript;
    build_transcript(&transcript, 1);

    if (!wabisabi_verify(&transcript, statements, WABISABI_CREDENTIAL_COUNT, req->proofs, WABISABI_CREDENTIAL_COUNT)) {
        free(statements);
        return WABISABI_ERR_INVALID_PROOF;
    }

    free(statements);

    /* Continue with post-verification transcript (same as C# which uses the
   * same transcript for Verify then Prove without resetting it) */

    wabisabi_knowledge_t* issue_knowledge = malloc(WABISABI_CREDENTIAL_COUNT * sizeof(wabisabi_knowledge_t));
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        uint8_t t_bytes[WABISABI_SCALAR_SIZE];
        /* Derive t from random_bytes + index */
        uint8_t seed[WABISABI_SCALAR_SIZE + 1];
        memcpy(seed, random_bytes, WABISABI_SCALAR_SIZE);
        seed[WABISABI_SCALAR_SIZE] = (uint8_t)i;
        sha256(seed, WABISABI_SCALAR_SIZE + 1, t_bytes);
        while (!secp256k1_ec_seckey_verify(WABISABI_CTX, t_bytes)) {
            sha256(t_bytes, WABISABI_SCALAR_SIZE, t_bytes);
        }
        issue_credential(&resp->issued[i], &issue_knowledge[i], issuer, &req->requested[i].ma, t_bytes);
    }

    wabisabi_prove(resp->proofs, &transcript, issue_knowledge, WABISABI_CREDENTIAL_COUNT, random_bytes,
                   WABISABI_SCALAR_SIZE);

    free(issue_knowledge);

    resp->n_issued = WABISABI_CREDENTIAL_COUNT;
    return WABISABI_OK;
}

wabisabi_error_t
wabisabi_issuer_state_handle_real(wabisabi_issuer_state_t* issuer, const wabisabi_real_request_t* req,
                                  wabisabi_response_t* resp, const uint8_t* random_bytes) {
    /* A real request either requests no credentials (presentation-only, e.g.
     * output registration) or the full WABISABI_CREDENTIAL_COUNT. */
    if (req->n_requested != 0 && req->n_requested != WABISABI_CREDENTIAL_COUNT) {
        return WABISABI_ERR_INVALID_CRED_COUNT;
    }

    /* Validate bit commitment count */
    for (int i = 0; i < req->n_requested; i++) {
        if (req->requested[i].n_bit_commitments != issuer->range_proof_width) {
            return WABISABI_ERR_INVALID_BIT_COMMITMENT;
        }
    }

    /* Reject a request that presents the same serial number twice: presenting
     * one credential more than once in a single request is a double spend. This
     * check is stateless (it only inspects the request), so it stays in the
     * library as defense-in-depth for every FFI caller. Cross-request reuse
     * detection needs a stateful nullifier set and is the caller's
     * responsibility — see wabisabi_ffi.h. */
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        for (int j = i + 1; j < WABISABI_CREDENTIAL_COUNT; j++) {
            if (wabisabi_ge_equal(&req->presented[i].s, &req->presented[j].s)) {
                return WABISABI_ERR_SERIAL_DUPLICATED;
            }
        }
    }

    /* Balance check: balance + delta must not go negative */
    if (issuer->balance + req->delta < 0) {
        return WABISABI_ERR_NEGATIVE_BALANCE;
    }

    /* Build statements */
    int n_stmt = 0;
    wabisabi_statement_t* statements = malloc((WABISABI_CREDENTIAL_COUNT * 2 + 1) * sizeof(wabisabi_statement_t));

    /* Credential show proofs */
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        wabisabi_ge_t z;
        wabisabi_compute_z(&z, &req->presented[i], &issuer->sk);
        wabisabi_show_credential_statement_into(&statements[n_stmt++], &req->presented[i], &z, &issuer->iparams);
    }

    /* Range proofs (none for a presentation-only request) */
    for (int i = 0; i < req->n_requested; i++) {
        wabisabi_range_proof_statement_into(&statements[n_stmt++], &req->requested[i].ma,
                                            req->requested[i].bit_commitments, issuer->range_proof_width);
    }

    /* Balance proof */
    {
        wabisabi_ge_t sum_ca = {.is_infinity = 1};
        wabisabi_ge_t sum_ma = {.is_infinity = 1};
        for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
            wabisabi_ge_add(&sum_ca, &sum_ca, &req->presented[i].ca);
        }
        for (int i = 0; i < req->n_requested; i++) {
            wabisabi_ge_add(&sum_ma, &sum_ma, &req->requested[i].ma);
        }

        wabisabi_scalar_t abs_delta;
        uint64_t abs_d = (uint64_t)(req->delta < 0 ? -req->delta : req->delta);
        memset(abs_delta.data, 0, WABISABI_SCALAR_SIZE);
        for (int i = 0; i < 8; i++) {
            abs_delta.data[31 - i] = (uint8_t)(abs_d >> (8 * i));
        }

        wabisabi_scalar_t delta_a;
        if (req->delta < 0) {
            wabisabi_scalar_negate(&delta_a, &abs_delta);
        } else {
            delta_a = abs_delta;
        }

        /* balance_tweak = delta_a * Gg */
        wabisabi_ge_t balance_tweak;
        wabisabi_ge_mul(&balance_tweak, &delta_a, &WABISABI_Gg);

        /* balance_commitment = balance_tweak + sum_Ca - sum_Ma */
        wabisabi_ge_t bc;
        wabisabi_ge_add(&bc, &balance_tweak, &sum_ca);
        wabisabi_ge_sub(&bc, &bc, &sum_ma);

        wabisabi_balance_proof_statement_into(&statements[n_stmt++], &bc);
    }

    wabisabi_transcript_t transcript;
    build_transcript(&transcript, 0);

    int ok = wabisabi_verify(&transcript, statements, n_stmt, req->proofs, req->n_proofs);

    if (!ok) {
        free(statements);
        return WABISABI_ERR_INVALID_PROOF;
    }

    free(statements);

    issuer->balance += req->delta;

    /* Continue with post-verification transcript (don't rebuild).
     * A presentation-only request (n_requested == 0) issues no credentials. */
    wabisabi_knowledge_t* issue_knowledge = malloc(WABISABI_CREDENTIAL_COUNT * sizeof(wabisabi_knowledge_t));
    for (int i = 0; i < req->n_requested; i++) {
        uint8_t t_bytes[WABISABI_SCALAR_SIZE];
        uint8_t seed[WABISABI_SCALAR_SIZE + 1];
        memcpy(seed, random_bytes, WABISABI_SCALAR_SIZE);
        seed[WABISABI_SCALAR_SIZE] = (uint8_t)i;
        sha256(seed, WABISABI_SCALAR_SIZE + 1, t_bytes);
        while (!secp256k1_ec_seckey_verify(WABISABI_CTX, t_bytes)) {
            sha256(t_bytes, WABISABI_SCALAR_SIZE, t_bytes);
        }
        issue_credential(&resp->issued[i], &issue_knowledge[i], issuer, &req->requested[i].ma, t_bytes);
    }

    wabisabi_prove(resp->proofs, &transcript, issue_knowledge, req->n_requested, random_bytes,
                   WABISABI_SCALAR_SIZE);

    free(issue_knowledge);

    resp->n_issued = req->n_requested;
    return WABISABI_OK;
}
