/* WabiSabi C library — stateless serialization API for cross-language interop.
 *
 * Wire format (all multi-byte integers are little-endian unless noted):
 *   GroupElement : WABISABI_GE_SIZE bytes     (compressed secp256k1; 0x00 = infinity)
 *   Scalar       : WABISABI_SCALAR_SIZE bytes  (big-endian, standard secp256k1 format)
 *   MAC          : [t:SCALAR_SIZE][V:GE_SIZE]  = WABISABI_MAC_SIZE bytes
 *   Proof        : [n_nonces:1][n_responses:1][nonces:n*GE_SIZE][responses:n*SCALAR_SIZE]
 *   IssuanceReq  : [Ma:GE_SIZE][bits:w*GE_SIZE]
 *   Presentation : [Ca][Cx0][Cx1][CV][S]       = WABISABI_PRESENTATION_SIZE bytes
 *   Credential   : [value:VALUE_SIZE][randomness:SCALAR_SIZE][mac:MAC_SIZE] =
 *                  WABISABI_CREDENTIAL_SIZE bytes
 *   SKBytes      : [w][wp][x0][x1][ya]          = WABISABI_SK_SIZE bytes
 *   IParamsBytes : [Cw][I]                      = WABISABI_IPARAMS_SIZE bytes
 *
 *   ZeroRequest  : [Ma_0][Ma_1][proof_0][proof_1]
 *   RealRequest  : [delta:VALUE_SIZE][n_presented:1][pres_0:PRESENTATION_SIZE]...[pres_{m-1}]
 *                  [n_requested:1][req_0]...[req_{n-1}][n_proofs:1][proofs...]
 *                  n_presented must be WABISABI_CREDENTIAL_COUNT for a real
 *                  request; any other count is rejected fail-fast with
 *                  WABISABI_ERR_INVALID_PRESENTATION_COUNT (mirroring the
 *                  managed issuer's presentation-count guard).
 *                  n_requested is 0 for a presentation-only request (output
 *                  registration: presents credentials, requests none) or
 *                  WABISABI_CREDENTIAL_COUNT for a normal request.
 *   Response     : [n_issued:1][mac_0]...[mac_{n-1}][proof_0]...[proof_{n-1}]
 *                  n_issued matches the request's n_requested (0 issued
 *                  credentials for a presentation-only request).
 *
 *   ValidationState (WABISABI_VALIDATION_SIZE bytes):
 *     [strobe_state:200][strobe_pos:1][strobe_pos_begin:1][strobe_cur_flags:1]
 *     [n_requested:4 LE]
 *     [req_0_value:8 LE][req_0_randomness:32][req_0_ma:33]
 *     [req_1_value:8 LE][req_1_randomness:32][req_1_ma:33]
 *
 *   MutableIssuerState (WABISABI_ISSUER_MSTATE_MAX_SIZE bytes):
 *     [balance:8 LE]
 *
 * NOTE: the issuer does NOT track serial numbers. Double-spend prevention
 * (rejecting duplicated or previously-seen serial numbers) is a policy concern
 * left to the caller — the presented serial numbers are available to the host
 * from the request it constructed, so it can maintain its own nullifier set.
 * The C library performs only the cryptographic verification and the balance
 * bookkeeping; the mutable issuer state it round-trips is just the balance.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* ---- Wire-format size constants ---- */
#ifndef WABISABI_SCALAR_SIZE
#define WABISABI_SCALAR_SIZE 32 /* secp256k1 scalar, big-endian */
#endif
#ifndef WABISABI_GE_SIZE
#define WABISABI_GE_SIZE 33 /* compressed secp256k1 point */
#endif
#ifndef WABISABI_VALUE_SIZE
#define WABISABI_VALUE_SIZE 8 /* 8-byte LE amount field */
#endif
#define WABISABI_RAND_SIZE    WABISABI_SCALAR_SIZE
#define WABISABI_SK_SIZE      (5 * WABISABI_SCALAR_SIZE) /* w + wp + x0 + x1 + ya */
#define WABISABI_IPARAMS_SIZE (2 * WABISABI_GE_SIZE)     /* Cw + I */
#ifndef WABISABI_MAC_SIZE
#define WABISABI_MAC_SIZE (WABISABI_SCALAR_SIZE + WABISABI_GE_SIZE)
#endif
#ifndef WABISABI_PRESENTATION_SIZE
#define WABISABI_PRESENTATION_SIZE (5 * WABISABI_GE_SIZE) /* Ca Cx0 Cx1 CV S */
#endif
#ifndef WABISABI_CREDENTIAL_SIZE
#define WABISABI_CREDENTIAL_SIZE (WABISABI_VALUE_SIZE + WABISABI_SCALAR_SIZE + WABISABI_MAC_SIZE)
#endif
#ifndef WABISABI_CREDENTIAL_COUNT
#define WABISABI_CREDENTIAL_COUNT 2
#endif

/* Compile-time wire-size sanity checks */
_Static_assert(WABISABI_MAC_SIZE == 65, "MAC size mismatch");
_Static_assert(WABISABI_PRESENTATION_SIZE == 165, "presentation size mismatch");
_Static_assert(WABISABI_CREDENTIAL_SIZE == 105, "credential size mismatch");
_Static_assert(WABISABI_SK_SIZE == 160, "SK size mismatch");
_Static_assert(WABISABI_IPARAMS_SIZE == 66, "iparams size mismatch");

/* Serialized client validation state size (fixed):
 *   strobe(203) + n_requested(4) + 2*(value(8)+randomness(32)+ma(33)) = 353 bytes */
#define WABISABI_VALIDATION_SIZE 353

/* Mutable issuer state: just the running balance (8 bytes, LE). Serial-number
 * tracking is the caller's responsibility (see the header comment above). */
#define WABISABI_ISSUER_MSTATE_MAX_SIZE 8

/* Upper bound on a serialized request/response for any range-proof width up to
 * WABISABI_MAX_RANGE_WIDTH. A real request grows with the range-proof width
 * (range proofs scale ~linearly with the number of bits); at the maximum width
 * it is ~21 KiB. 64 KiB is always sufficient and is the recommended size for
 * the req_out / resp_out buffers. NOTE: a fixed 16 KiB buffer is NOT enough —
 * a real request for a large max_amount (e.g. 43,000 BTC -> width 42 -> ~17.6
 * KiB) overruns it. Always pass the true buffer capacity (see *_cap params). */
#define WABISABI_MAX_REQUEST_SIZE (64 * 1024)

/* ---- Error codes ---- */
typedef enum {
    WABISABI_OK = 0,
    WABISABI_ERR_NULL_PTR = 1,       /* null pointer argument */
    WABISABI_ERR_INVALID_LENGTH = 2, /* input/output buffer too short */
    WABISABI_ERR_PARSE = 3,          /* malformed group element or scalar */
    WABISABI_ERR_INVALID_PROOF = 4,
    WABISABI_ERR_INVALID_CRED_COUNT = 5,
    WABISABI_ERR_INVALID_BIT_COMMITMENT = 6,
    /* Produced when a single request presents the same serial number twice
     * (a stateless within-request double-spend guard). */
    WABISABI_ERR_SERIAL_DUPLICATED = 7,
    /* 8/10 are retained for ABI stability but are no longer produced by the
     * issuer: cross-request serial-reuse detection and the capacity cap moved
     * to the caller (see the MutableIssuerState note above). */
    WABISABI_ERR_SERIAL_REUSED = 8,
    WABISABI_ERR_NEGATIVE_BALANCE = 9,
    WABISABI_ERR_SERIAL_SET_FULL = 10,
    WABISABI_ERR_BUFFER_TOO_SMALL = 11, /* an output buffer capacity is too small for the result */
    WABISABI_ERR_ALLOC = 12, /* heap allocation failed (no longer used by the issuer) */
    /* A real request presented a number of credentials other than
     * WABISABI_CREDENTIAL_COUNT (fail-fast presentation-count guard). */
    WABISABI_ERR_INVALID_PRESENTATION_COUNT = 13,
    /* The coordinator's response issued a number of credentials different from
     * the number the client requested (mirrors the managed client's
     * IssuedCredentialNumberMismatch guard in HandleResponse). */
    WABISABI_ERR_ISSUED_COUNT_MISMATCH = 14,
    /* A real request presented the same credential (identical MAC) more than
     * once (mirrors the managed client's CredentialToPresentDuplicated guard in
     * CreateRequest). */
    WABISABI_ERR_CREDENTIAL_DUPLICATED = 15,
} wabisabi_error_t;

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize WabiSabi runtime (context + generators). Call once before any other function. */
void wabisabi_init(void);

/** Free WabiSabi runtime resources. */
void wabisabi_cleanup(void);

/**
 * Compute issuer parameters (Cw, I) from secret key bytes.
 * sk_bytes  : WABISABI_SK_SIZE bytes     (5 scalars: w, wp, x0, x1, ya)
 * out_bytes : WABISABI_IPARAMS_SIZE bytes (2 group elements: Cw, I)
 */
wabisabi_error_t wabisabi_iparams_from_sk(const uint8_t* sk_bytes, uint8_t* out_bytes);

/* ---- Issuer (stateless) ---- */

/**
 * Handle a zero (bootstrap) credential request.
 *
 * sk_bytes      : WABISABI_SK_SIZE bytes — coordinator secret key.
 * max_amount    : upper bound on credential values.
 * mstate_in     : serialized mutable state from prior call, or NULL/0 for initial state.
 * mstate_in_len : byte length of mstate_in (0 for initial state).
 * req_bytes     : wire-encoded ZeroRequest.
 * req_len       : byte length of req_bytes.
 * rand_bytes    : WABISABI_RAND_SIZE bytes of fresh randomness for MAC issuance.
 * resp_out      : output buffer for the response (use WABISABI_MAX_REQUEST_SIZE bytes).
 * resp_out_cap  : capacity of resp_out in bytes; returns WABISABI_ERR_BUFFER_TOO_SMALL if too small.
 * resp_len_out  : set to actual response length on success.
 * mstate_out    : output buffer for updated mutable state (WABISABI_ISSUER_MSTATE_MAX_SIZE bytes).
 * mstate_out_cap: capacity of mstate_out in bytes; returns WABISABI_ERR_BUFFER_TOO_SMALL if too small.
 * mstate_out_len: set to actual mutable state length on success.
 */
wabisabi_error_t wabisabi_issuer_handle_zero(
    const uint8_t* sk_bytes,
    int64_t max_amount,
    const uint8_t* mstate_in, int mstate_in_len,
    const uint8_t* req_bytes, int req_len,
    const uint8_t* rand_bytes,
    uint8_t* resp_out, int resp_out_cap, int* resp_len_out,
    uint8_t* mstate_out, int mstate_out_cap, int* mstate_out_len);

/**
 * Handle a real credential request. Same parameters as wabisabi_issuer_handle_zero.
 */
wabisabi_error_t wabisabi_issuer_handle_real(
    const uint8_t* sk_bytes,
    int64_t max_amount,
    const uint8_t* mstate_in, int mstate_in_len,
    const uint8_t* req_bytes, int req_len,
    const uint8_t* rand_bytes,
    uint8_t* resp_out, int resp_out_cap, int* resp_len_out,
    uint8_t* mstate_out, int mstate_out_cap, int* mstate_out_len);

/* ---- Client (stateless) ---- */

/**
 * Create a zero (bootstrap) credential request.
 *
 * rand_bytes   : WABISABI_RAND_SIZE bytes of randomness.
 * req_out      : output buffer for the request (use WABISABI_MAX_REQUEST_SIZE bytes).
 * req_out_cap  : capacity of req_out in bytes; returns WABISABI_ERR_BUFFER_TOO_SMALL if too small.
 * req_len_out  : set to actual request length on success.
 * val_out      : output buffer for validation state; must be WABISABI_VALIDATION_SIZE bytes.
 *                Pass this to wabisabi_client_handle_response after receiving the issuer response.
 */
wabisabi_error_t wabisabi_client_create_zero_request(
    const uint8_t* rand_bytes,
    uint8_t* req_out, int req_out_cap, int* req_len_out,
    uint8_t val_out[WABISABI_VALIDATION_SIZE]);

/**
 * Create a real credential request (present old credentials, request new ones).
 *
 * iparams_bytes : WABISABI_IPARAMS_SIZE bytes — issuer public parameters.
 * max_amount    : upper bound used to compute range-proof width.
 * amounts       : array of n_amounts int64_t values to request.
 * creds_bytes   : serialized credentials (n_creds × WABISABI_CREDENTIAL_SIZE bytes).
 * rand_bytes    : WABISABI_RAND_SIZE bytes of randomness.
 * req_out       : output buffer for the request (use WABISABI_MAX_REQUEST_SIZE bytes — a real
 *                 request grows with the range-proof width and can exceed 16 KiB).
 * req_out_cap   : capacity of req_out in bytes; returns WABISABI_ERR_BUFFER_TOO_SMALL if too small.
 * req_len_out   : set to actual request length on success.
 * val_out       : output buffer for validation state; must be WABISABI_VALIDATION_SIZE bytes.
 */
wabisabi_error_t wabisabi_client_create_real_request(
    const uint8_t* iparams_bytes,
    int64_t max_amount,
    const int64_t* amounts, int n_amounts,
    const uint8_t* creds_bytes, int n_creds,
    const uint8_t* rand_bytes,
    uint8_t* req_out, int req_out_cap, int* req_len_out,
    uint8_t val_out[WABISABI_VALIDATION_SIZE]);

/**
 * Process an issuer response and extract credentials.
 *
 * iparams_bytes : WABISABI_IPARAMS_SIZE bytes — issuer public parameters (for proof verification).
 * resp_bytes    : wire-encoded Response from the issuer.
 * resp_len      : byte length of resp_bytes.
 * val_bytes     : WABISABI_VALIDATION_SIZE bytes — validation state from the corresponding create call.
 * creds_out     : output buffer (WABISABI_CREDENTIAL_COUNT × WABISABI_CREDENTIAL_SIZE bytes).
 * creds_out_cap : capacity of creds_out in bytes; returns WABISABI_ERR_BUFFER_TOO_SMALL if too small.
 * n_creds_out   : set to number of credentials on success (always WABISABI_CREDENTIAL_COUNT).
 */
wabisabi_error_t wabisabi_client_handle_response(
    const uint8_t* iparams_bytes,
    const uint8_t* resp_bytes, int resp_len,
    const uint8_t val_bytes[WABISABI_VALIDATION_SIZE],
    uint8_t* creds_out, int creds_out_cap, int* n_creds_out);

#ifdef __cplusplus
}
#endif
