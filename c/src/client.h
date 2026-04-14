/* WabiSabi client (wallet side).
 * Matches WabiSabiClient.cs.
 */
#pragma once
#include "credential.h"
#include "issuer.h" /* for request/response types */
#include "mac.h"
#include "proof.h"
#include "wabisabi_types.h"

/* Validation data needed to verify coordinator's response */
typedef struct {
    wabisabi_transcript_t transcript;
    wabisabi_issuance_validation_t requested[WABISABI_CREDENTIAL_COUNT];
    int n_requested;
} wabisabi_response_validation_t;

/* Client state */
typedef struct {
    wabisabi_iparams_t iparams;
    int range_proof_width;
} wabisabi_client_state_t;

void wabisabi_client_state_init(wabisabi_client_state_t* c, const wabisabi_iparams_t* iparams,
                                int64_t range_proof_upper_bound);

/* Create a bootstrap request (zero-value credentials).
 * random_bytes: 32+ bytes of randomness.
 * out_req: populated with the zero-credential request.
 * out_val: populated with state needed to validate the response.
 */
void wabisabi_client_state_create_zero_request(wabisabi_client_state_t* c, const uint8_t* random_bytes,
                                               wabisabi_zero_request_t* out_req,
                                               wabisabi_response_validation_t* out_val);

/* Create a "presentation only" real request (spending credentials, no new issuance).
 * credentials_to_present: array of credentials to spend.
 * n_present: count.
 */
void wabisabi_client_state_create_present_request(wabisabi_client_state_t* c,
                                                  const wabisabi_credential_t* credentials_to_present, int n_present,
                                                  const uint8_t* random_bytes, wabisabi_real_request_t* out_req,
                                                  wabisabi_response_validation_t* out_val);

/* Create a real request with specific amounts to request.
 * amounts_to_request: values for new credentials (padded with zeros to k).
 * n_amounts: count (may be less than k).
 * credentials_to_present: credentials to spend.
 * n_present: count.
 */
void wabisabi_client_state_create_real_request(wabisabi_client_state_t* c, const int64_t* amounts_to_request,
                                               int n_amounts, const wabisabi_credential_t* credentials_to_present,
                                               int n_present, const uint8_t* random_bytes,
                                               wabisabi_real_request_t* out_req,
                                               wabisabi_response_validation_t* out_val);

/* Validate coordinator response and extract new credentials.
 * Returns WABISABI_OK on success; credentials stored in out_credentials[k].
 */
wabisabi_error_t
wabisabi_client_state_handle_response(wabisabi_client_state_t* c, const wabisabi_response_t* response,
                                      const wabisabi_response_validation_t* validation,
                                      wabisabi_credential_t out_credentials[WABISABI_CREDENTIAL_COUNT]);
