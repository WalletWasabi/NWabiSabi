/* Integration test: full WabiSabi protocol round-trip.
 * Tests the complete flow: bootstrap → issue → spend.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "credential.h"
#include "generators.h"
#include "issuer.h"
#include "mac.h"
#include "proof.h"
#include "sha256.h"
#include "wabisabi_types.h"

/* Simple deterministic "random" for testing */
static uint8_t g_test_rng_state[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                       0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                       0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static void
next_random(uint8_t* out) {
    /* SHA-256 chain */
    uint8_t tmp[32];
    sha256(g_test_rng_state, 32, tmp);
    memcpy(g_test_rng_state, tmp, 32);
    memcpy(out, tmp, 32);
}

static void
test_generators(void) {
    printf("Testing generators...\n");

    /* Verify generators are not infinity */
    assert(!WABISABI_Gw.is_infinity);
    assert(!WABISABI_Gwp.is_infinity);
    assert(!WABISABI_Gx0.is_infinity);
    assert(!WABISABI_Gx1.is_infinity);
    assert(!WABISABI_GV.is_infinity);
    assert(!WABISABI_Gg.is_infinity);
    assert(!WABISABI_Gh.is_infinity);
    assert(!WABISABI_Ga.is_infinity);
    assert(!WABISABI_Gs.is_infinity);

    /* Verify all generators are distinct */
    assert(!wabisabi_ge_equal(&WABISABI_Gw, &WABISABI_Gwp));
    assert(!wabisabi_ge_equal(&WABISABI_Gg, &WABISABI_Gh));

    /* Verify 2^0 * Gh != 2^1 * Gh */
    assert(!wabisabi_ge_equal(&WABISABI_NEG_GH_POW2[0], &WABISABI_NEG_GH_POW2[1]));

    printf("  Generators OK\n");
}

static void
test_scalar_ops(void) {
    printf("Testing scalar operations...\n");

    wabisabi_scalar_t zero = WABISABI_SCALAR_ZERO;
    wabisabi_scalar_t one = WABISABI_SCALAR_ONE;

    /* 0 + 1 = 1 */
    wabisabi_scalar_t r;
    wabisabi_scalar_add(&r, &zero, &one);
    assert(memcmp(r.data, one.data, 32) == 0);

    /* 1 + 0 = 1 */
    wabisabi_scalar_add(&r, &one, &zero);
    assert(memcmp(r.data, one.data, 32) == 0);

    /* 1 * 1 = 1 */
    wabisabi_scalar_mul(&r, &one, &one);
    assert(memcmp(r.data, one.data, 32) == 0);

    /* -1 + 1 = 0 */
    wabisabi_scalar_t neg_one;
    wabisabi_scalar_negate(&neg_one, &one);
    wabisabi_scalar_add(&r, &neg_one, &one);
    assert(wabisabi_scalar_is_zero(&r));

    /* 0 * anything = 0 */
    wabisabi_scalar_mul(&r, &zero, &one);
    assert(wabisabi_scalar_is_zero(&r));

    printf("  Scalar ops OK\n");
}

static void
test_group_ops(void) {
    printf("Testing group element operations...\n");

    /* G + (-G) = infinity */
    wabisabi_ge_t neg_G;
    wabisabi_ge_negate(&neg_G, &WABISABI_G);
    wabisabi_ge_t sum;
    wabisabi_ge_add(&sum, &WABISABI_G, &neg_G);
    assert(sum.is_infinity);

    /* 1*G = G */
    wabisabi_ge_t one_G;
    wabisabi_ge_mul_base(&one_G, &WABISABI_SCALAR_ONE);
    assert(wabisabi_ge_equal(&one_G, &WABISABI_G));

    /* 0*G = infinity */
    wabisabi_ge_t zero_G;
    wabisabi_ge_mul_base(&zero_G, &WABISABI_SCALAR_ZERO);
    assert(zero_G.is_infinity);

    printf("  Group ops OK\n");
}

static void
test_pedersen(void) {
    printf("Testing Pedersen commitments...\n");

    wabisabi_scalar_t a, r;
    next_random(a.data);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, a.data)) {
        next_random(a.data);
    }
    next_random(r.data);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, r.data)) {
        next_random(r.data);
    }

    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, &a, &r);
    assert(!ma.is_infinity);

    /* ma = a*Gg + r*Gh */
    wabisabi_ge_t aGg, rGh, expected;
    wabisabi_ge_mul(&aGg, &a, &WABISABI_Gg);
    wabisabi_ge_mul(&rGh, &r, &WABISABI_Gh);
    wabisabi_ge_add(&expected, &aGg, &rGh);
    assert(wabisabi_ge_equal(&ma, &expected));

    printf("  Pedersen OK\n");
}

static void
test_mac(void) {
    printf("Testing MAC...\n");

    uint8_t rand1[32], rand2[32], rand3[32], rand4[32], rand5[32], rand6[32];
    next_random(rand1);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand1)) {
        next_random(rand1);
    }
    next_random(rand2);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand2)) {
        next_random(rand2);
    }
    next_random(rand3);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand3)) {
        next_random(rand3);
    }
    next_random(rand4);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand4)) {
        next_random(rand4);
    }
    next_random(rand5);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand5)) {
        next_random(rand5);
    }
    next_random(rand6);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand6)) {
        next_random(rand6);
    }

    wabisabi_sk_t sk;
    memcpy(sk.w.data, rand1, 32);
    memcpy(sk.wp.data, rand2, 32);
    memcpy(sk.x0.data, rand3, 32);
    memcpy(sk.x1.data, rand4, 32);
    memcpy(sk.ya.data, rand5, 32);

    wabisabi_scalar_t amount_scalar = WABISABI_SCALAR_ZERO;
    amount_scalar.data[31] = 100; /* value = 100 */
    wabisabi_scalar_t r;
    memcpy(r.data, rand6, 32);

    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, &amount_scalar, &r);

    /* Generate t */
    uint8_t t_bytes[32];
    next_random(t_bytes);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, t_bytes)) {
        next_random(t_bytes);
    }
    wabisabi_scalar_t t;
    memcpy(t.data, t_bytes, 32);

    wabisabi_mac_t mac;
    wabisabi_mac_compute(&mac, &sk, &ma, &t);
    assert(!mac.v.is_infinity);

    printf("  MAC OK\n");
}

static void
test_zero_proof(void) {
    printf("Testing zero proof (bootstrap)...\n");

    uint8_t r_bytes[32];
    next_random(r_bytes);
    while (!secp256k1_ec_seckey_verify(WABISABI_CTX, r_bytes)) {
        next_random(r_bytes);
    }

    wabisabi_scalar_t r;
    memcpy(r.data, r_bytes, 32);
    wabisabi_ge_t ma;
    wabisabi_ge_mul(&ma, &r, &WABISABI_Gh);

    wabisabi_knowledge_t kn = wabisabi_zero_proof_knowledge(&ma, &r);

    uint8_t rnd[32];
    next_random(rnd);

    wabisabi_transcript_t t1, t2;
    wabisabi_transcript_init(&t1, (const uint8_t*)"test", 4);
    wabisabi_transcript_clone(&t2, &t1);

    wabisabi_proof_t proof;
    wabisabi_prove(&proof, &t1, &kn, 1, rnd, 32);

    wabisabi_statement_t stmt = wabisabi_zero_proof_statement(&ma);
    int ok = wabisabi_verify(&t2, &stmt, 1, &proof, 1);
    assert(ok);

    printf("  Zero proof OK\n");
}

static void
test_full_protocol(void) {
    printf("Testing full protocol (bootstrap + spend)...\n");

    /* Setup secret key */
    uint8_t rand_bytes[5][32];
    for (int i = 0; i < 5; i++) {
        next_random(rand_bytes[i]);
        while (!secp256k1_ec_seckey_verify(WABISABI_CTX, rand_bytes[i])) {
            next_random(rand_bytes[i]);
        }
    }

    wabisabi_sk_t sk;
    memcpy(sk.w.data, rand_bytes[0], 32);
    memcpy(sk.wp.data, rand_bytes[1], 32);
    memcpy(sk.x0.data, rand_bytes[2], 32);
    memcpy(sk.x1.data, rand_bytes[3], 32);
    memcpy(sk.ya.data, rand_bytes[4], 32);

    long max_amount = 1000000;

    /* Initialize issuer */
    wabisabi_issuer_state_t issuer;
    wabisabi_issuer_state_init(&issuer, &sk, max_amount);

    /* Initialize client */
    wabisabi_iparams_t iparams;
    wabisabi_compute_iparams(&iparams, &sk);
    wabisabi_client_state_t client;
    wabisabi_client_state_init(&client, &iparams, max_amount);

    /* --- Phase 1: Bootstrap (zero-value credentials) --- */
    printf("  Phase 1: Bootstrap...\n");

    uint8_t client_rand[32];
    next_random(client_rand);
    wabisabi_zero_request_t zero_req;
    wabisabi_response_validation_t zero_val;
    wabisabi_client_state_create_zero_request(&client, client_rand, &zero_req, &zero_val);

    uint8_t issuer_rand[32];
    next_random(issuer_rand);
    wabisabi_response_t zero_resp;
    wabisabi_error_t err = wabisabi_issuer_state_handle_zero(&issuer, &zero_req, &zero_resp, issuer_rand);
    if (err != WABISABI_OK) {
        printf("  ERROR: issuer rejected zero request (code %d)\n", err);
        assert(0);
    }

    wabisabi_credential_t credentials[WABISABI_CREDENTIAL_COUNT];
    err = wabisabi_client_state_handle_response(&client, &zero_resp, &zero_val, credentials);
    if (err != WABISABI_OK) {
        printf("  ERROR: client rejected issuer response (code %d)\n", err);
        assert(0);
    }

    /* Verify credentials have value 0 */
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        assert(credentials[i].value == 0);
    }

    printf("  Bootstrap OK — got %d zero-value credentials\n", WABISABI_CREDENTIAL_COUNT);

    /* --- Phase 2: Input registration (request value credentials) --- */
    printf("  Phase 2: Input registration...\n");

    long amounts_to_request[] = {500000, 300000};
    uint8_t client_rand2[32];
    next_random(client_rand2);
    wabisabi_real_request_t real_req;
    wabisabi_response_validation_t real_val;

    wabisabi_client_state_create_real_request(&client, amounts_to_request, 2, credentials, WABISABI_CREDENTIAL_COUNT,
                                              client_rand2, &real_req, &real_val);

    uint8_t issuer_rand2[32];
    next_random(issuer_rand2);
    wabisabi_response_t real_resp;
    err = wabisabi_issuer_state_handle_real(&issuer, &real_req, &real_resp, issuer_rand2);
    if (err != WABISABI_OK) {
        printf("  ERROR: issuer rejected real request (code %d)\n", err);
        assert(0);
    }

    wabisabi_credential_t new_credentials[WABISABI_CREDENTIAL_COUNT];
    err = wabisabi_client_state_handle_response(&client, &real_resp, &real_val, new_credentials);
    if (err != WABISABI_OK) {
        printf("  ERROR: client rejected issuer real response (code %d)\n", err);
        assert(0);
    }

    long total = 0;
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        printf("    Credential[%d]: value=%ld\n", i, new_credentials[i].value);
        total += new_credentials[i].value;
    }
    printf("  Total value: %ld (expected: 800000)\n", total);
    assert(total == 800000);

    printf("  Full protocol OK\n");
}

int run_compat_tests(void);

int
main(void) {
    printf("=== WabiSabi C Implementation Tests ===\n\n");

    wabisabi_ctx_init();
    printf("Initializing generators (may take a moment)...\n");
    wabisabi_generators_init();
    printf("Generators initialized.\n\n");

    test_generators();
    test_scalar_ops();
    test_group_ops();
    test_pedersen();
    test_mac();
    test_zero_proof();
    test_full_protocol();

    printf("\n=== Integration tests passed ===\n\n");

    int compat_failures = run_compat_tests();

    wabisabi_ctx_cleanup();
    if (compat_failures > 0) {
        printf("\n=== FAILED: %d compat test(s) failed ===\n", compat_failures);
        return 1;
    }
    printf("\n=== All tests passed ===\n");
    return 0;
}
