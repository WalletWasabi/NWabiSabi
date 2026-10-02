/* Presentation-only request regression test (uninitialized validation slot).
 *
 * The client validation state has a FIXED wire layout that always serializes
 * WABISABI_CREDENTIAL_COUNT requested slots (value, randomness, ma) — see
 * write_validation_state in ffi.c. A presentation-only request (output
 * registration: present credentials, request none -> n_requested == 0) fills
 * none of those slots, so they used to be serialized straight from
 * uninitialized memory. When that stale memory decoded as a non-infinity group
 * element whose x-coordinate is zero, wabisabi_ge_serialize handed secp256k1 a
 * zero pubkey and it aborted:
 *   "[libsecp256k1] illegal argument: !secp256k1_fe_is_zero(&ge->x)"
 * On Linux the memory happened to hold values that dodged it; on Windows (whose
 * stack/heap is not zeroed) it aborted the whole test run (exit code 3). The fix
 * initializes every validation slot (value 0, randomness 0, ma = infinity).
 *
 * This test reproduces the condition deterministically on any platform by
 * controlling that memory itself: it poisons a validation struct so each
 * requested slot's `ma` is a NON-infinity group element (is_infinity == 0), then
 * issues a presentation-only request (n_amounts == 0) through the internal client
 * API with that struct as the output. The fix must overwrite every unused slot
 * with the infinity element; without it the poisoned non-infinity ma survives
 * (and, on the FFI path, is what write_validation_state fed to secp256k1). The
 * test asserts every requested slot is the infinity element afterwards.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "credential.h"
#include "generators.h"
#include "issuer.h"
#include "proof.h"
#include "rand_stream.h"
#include "wabisabi_types.h"

/* Deterministic 32-byte seed for the rand stream (content is irrelevant here). */
static void
seed_stream(wabisabi_rand_stream_t* s, uint8_t fill) {
    uint8_t seed[WABISABI_SCALAR_SIZE];
    memset(seed, fill, sizeof(seed));
    wabisabi_rand_stream_init(s, seed);
}

int run_presentation_only_tests(void);

int
run_presentation_only_tests(void) {
    printf("Testing presentation-only request (uninitialized validation-slot regression)...\n");

    const int64_t max_amount = 1000000;

    /* Secret key + issuer/client setup. Distinct, valid (nonzero, < order) keys. */
    wabisabi_sk_t sk;
    memset(sk.w.data, 0x10, WABISABI_SCALAR_SIZE);
    memset(sk.wp.data, 0x11, WABISABI_SCALAR_SIZE);
    memset(sk.x0.data, 0x12, WABISABI_SCALAR_SIZE);
    memset(sk.x1.data, 0x13, WABISABI_SCALAR_SIZE);
    memset(sk.ya.data, 0x14, WABISABI_SCALAR_SIZE);

    wabisabi_issuer_state_t issuer;
    wabisabi_issuer_state_init(&issuer, &sk, max_amount);

    wabisabi_iparams_t iparams;
    wabisabi_compute_iparams(&iparams, &sk);
    wabisabi_client_state_t client;
    wabisabi_client_state_init(&client, &iparams, max_amount);

    /* Bootstrap to obtain credentials to present. */
    wabisabi_rand_stream_t rng;
    seed_stream(&rng, 0x42);
    wabisabi_zero_request_t zero_req;
    wabisabi_response_validation_t zero_val;
    wabisabi_client_state_create_zero_request(&client, &rng, &zero_req, &zero_val);

    wabisabi_rand_stream_t irng;
    seed_stream(&irng, 0x37);
    wabisabi_response_t zero_resp;
    if (wabisabi_issuer_state_handle_zero(&issuer, &zero_req, &zero_resp, &irng) != WABISABI_OK) {
        printf("  ERROR: issuer rejected zero request\n");
        return 1;
    }
    wabisabi_credential_t creds[WABISABI_CREDENTIAL_COUNT];
    if (wabisabi_client_state_handle_response(&client, &zero_resp, &zero_val, creds) != WABISABI_OK) {
        printf("  ERROR: client rejected zero response\n");
        return 1;
    }

    /* Poison the output validation struct: make every requested slot's ma a
     * NON-infinity group element (is_infinity == 0 with a non-zero pk), exactly
     * the state the fix must clobber. */
    wabisabi_response_validation_t pres_val;
    memset(&pres_val, 0x11, sizeof(pres_val));
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        pres_val.requested[i].ma.is_infinity = 0;
    }

    /* Presentation-only request: present credentials, request none. */
    wabisabi_rand_stream_t crng;
    seed_stream(&crng, 0x5a);
    wabisabi_real_request_t* pres_req = malloc(sizeof(*pres_req));
    if (!pres_req) {
        printf("  ERROR: allocation failed\n");
        return 1;
    }
    wabisabi_client_state_create_real_request(&client, NULL, 0, creds, WABISABI_CREDENTIAL_COUNT,
                                              &crng, pres_req, &pres_val);

    int rc = 0;
    if (pres_req->n_requested != 0) {
        printf("  ERROR: presentation-only request issued %d credentials (expected 0)\n", pres_req->n_requested);
        rc = 1;
    }
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        if (!pres_val.requested[i].ma.is_infinity) {
            printf("  ERROR: unused validation slot %d left as a non-infinity ma "
                   "(would be serialized to secp256k1 -> abort)\n", i);
            rc = 1;
        }
    }
    free(pres_req);

    if (rc == 0) {
        printf("  Presentation-only request OK — unused validation slots reset to infinity\n");
    }
    return rc;
}
