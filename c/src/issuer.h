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

/* Serial number set (simple open-addressing hash table) */
typedef struct {
    uint8_t entries[WABISABI_MAX_SERIAL_NUMBERS][WABISABI_GE_SIZE]; /* compressed points */
    int used[WABISABI_MAX_SERIAL_NUMBERS];
    int count;
} wabisabi_serial_set_t;

int wabisabi_serial_set_contains(const wabisabi_serial_set_t* set, const wabisabi_ge_t* s);
int wabisabi_serial_set_insert(wabisabi_serial_set_t* set, const wabisabi_ge_t* s);
void wabisabi_serial_set_remove(wabisabi_serial_set_t* set, const wabisabi_ge_t* s);

/* ---- Issuer state ---- */
typedef struct {
    wabisabi_sk_t sk;
    wabisabi_iparams_t iparams;
    int64_t max_amount;
    int range_proof_width;
    int64_t balance;
    wabisabi_serial_set_t serial_numbers;
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
