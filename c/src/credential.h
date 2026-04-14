/* Anonymous credential operations.
 * Matches Credential.cs and CredentialPresentation.cs.
 */
#pragma once
#include "mac.h"
#include "proof.h"
#include "wabisabi_types.h"

/* An anonymous credential: (value, randomness, mac) */
typedef struct {
    int64_t value;
    wabisabi_scalar_t randomness;
    wabisabi_mac_t mac;
} wabisabi_credential_t;

/* A credential request for issuance */
typedef struct {
    wabisabi_ge_t ma; /* Pedersen commitment to amount */
    wabisabi_ge_t bit_commitments[WABISABI_MAX_RANGE_WIDTH];
    int n_bit_commitments;
} wabisabi_issuance_request_t;

/* Compute Z for a presentation: CV - (w*Gw + x0*Cx0 + x1*Cx1 + ya*Ca) */
void wabisabi_compute_z(wabisabi_ge_t* z_out, const wabisabi_presentation_t* p, const wabisabi_sk_t* sk);

/* Validation data for checking coordinator response */
typedef struct {
    int64_t value;
    wabisabi_scalar_t randomness;
    wabisabi_ge_t ma;
} wabisabi_issuance_validation_t;
