/* Credential issuer (coordinator side).
 * Matches CredentialIssuer.cs.
 *
 * The issuer is stateful: it tracks used serial numbers to prevent
 * double-spending, and maintains a balance to prevent inflation.
 */
#pragma once
#include "../include/wabisabi_ffi.h"
#include "credential.h"
#include "mac.h"
#include "proof.h"
#include "wabisabi_types.h"

/* ---- Request / Response message types ---- */

/* Zero-value credential request (bootstrap, no presentations) */
typedef struct {
    wabisabi_issuance_request_t requested[WABISABI_CREDENTIAL_COUNT];
    wabisabi_proof_t proofs[WABISABI_CREDENTIAL_COUNT];
} wabisabi_zero_request_t;

/* Real credential request */
typedef struct {
    int64_t delta; /* amount delta */
    wabisabi_presentation_t presented[WABISABI_CREDENTIAL_COUNT];
    /* Number of requested credentials: 0 for a presentation-only request
     * (output registration) or WABISABI_CREDENTIAL_COUNT for a normal one. */
    int n_requested;
    wabisabi_issuance_request_t requested[WABISABI_CREDENTIAL_COUNT];
    wabisabi_proof_t proofs[/* presentations + range + balance */
                            WABISABI_CREDENTIAL_COUNT * 2 + 1];
    int n_proofs;
} wabisabi_real_request_t;

/* Coordinator response */
typedef struct {
    /* Number of issued credentials; mirrors the request's n_requested. */
    int n_issued;
    wabisabi_mac_t issued[WABISABI_CREDENTIAL_COUNT];
    wabisabi_proof_t proofs[WABISABI_CREDENTIAL_COUNT]; /* issuer params proofs */
} wabisabi_response_t;

/* ---- Issuer state ----
 *
 * The issuer does NOT track serial numbers; double-spend prevention is left to
 * the caller (see wabisabi_ffi.h). The only mutable state is the balance, so
 * this struct is small and can live on the stack. */
typedef struct {
    wabisabi_sk_t sk;
    wabisabi_iparams_t iparams;
    int64_t max_amount;
    int range_proof_width;
    int64_t balance;
} wabisabi_issuer_state_t;

/* Initialize issuer with secret key (must be non-zero scalars) */
void wabisabi_issuer_state_init(wabisabi_issuer_state_t* issuer, const wabisabi_sk_t* sk, int64_t max_amount);

/* Handle a zero-value (bootstrap) request.
 * random_bytes: 32 bytes of randomness for issuing t values.
 */
wabisabi_error_t wabisabi_issuer_state_handle_zero(wabisabi_issuer_state_t* issuer, const wabisabi_zero_request_t* req,
                                                   wabisabi_response_t* resp, const uint8_t* random_bytes);

/* Handle a real credential request */
wabisabi_error_t wabisabi_issuer_state_handle_real(wabisabi_issuer_state_t* issuer, const wabisabi_real_request_t* req,
                                                   wabisabi_response_t* resp, const uint8_t* random_bytes);
