/* WabiSabi client — matches WabiSabiClient.cs */
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "generators.h"
#include "sha256.h"

static int
ceil_log2_client(int64_t v) {
    int w = 0;
    int64_t n = 1;
    while (n < v) {
        n <<= 1;
        w++;
    }
    return w;
}

static void
build_transcript(wabisabi_transcript_t* t, int is_null) {
    char label[64];
    snprintf(label, sizeof(label), "UnifiedRegistration/%d/%s", WABISABI_CREDENTIAL_COUNT, is_null ? "True" : "False");
    wabisabi_transcript_init(t, (const uint8_t*)label, strlen(label));
}

void
wabisabi_client_state_init(wabisabi_client_state_t* c, const wabisabi_iparams_t* iparams,
                           int64_t range_proof_upper_bound) {
    c->iparams = *iparams;
    c->range_proof_width = ceil_log2_client(range_proof_upper_bound);
}

void
wabisabi_client_state_create_zero_request(wabisabi_client_state_t* c, const uint8_t* random_bytes,
                                          wabisabi_zero_request_t* out_req, wabisabi_response_validation_t* out_val) {
    (void)c; /* iparams not needed for zero-value credentials */
    wabisabi_knowledge_t knowledge[WABISABI_CREDENTIAL_COUNT];

    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        /* Derive randomness for each credential */
        uint8_t seed[WABISABI_SCALAR_SIZE + 1];
        memcpy(seed, random_bytes, WABISABI_SCALAR_SIZE);
        seed[WABISABI_SCALAR_SIZE] = (uint8_t)i;
        uint8_t r_bytes[WABISABI_SCALAR_SIZE];
        sha256(seed, WABISABI_SCALAR_SIZE + 1, r_bytes);
        while (!secp256k1_ec_seckey_verify(WABISABI_CTX, r_bytes)) {
            sha256(r_bytes, WABISABI_SCALAR_SIZE, r_bytes);
        }

        wabisabi_scalar_t randomness;
        memcpy(randomness.data, r_bytes, WABISABI_SCALAR_SIZE);

        /* ma = randomness * Gh */
        wabisabi_ge_t ma;
        wabisabi_ge_mul(&ma, &randomness, &WABISABI_Gh);

        knowledge[i] = wabisabi_zero_proof_knowledge(&ma, &randomness);

        out_req->requested[i].ma = ma;
        out_req->requested[i].n_bit_commitments = 0;

        out_val->requested[i].value = 0;
        out_val->requested[i].randomness = randomness;
        out_val->requested[i].ma = ma;
    }

    /* Transcript for proving — advances through zero proof */
    wabisabi_transcript_t prove_transcript;
    build_transcript(&prove_transcript, 1);

    /* Derive prove randomness */
    uint8_t prove_rand[WABISABI_SCALAR_SIZE];
    uint8_t seed2[WABISABI_SCALAR_SIZE + 1];
    memcpy(seed2, random_bytes, WABISABI_SCALAR_SIZE);
    seed2[WABISABI_SCALAR_SIZE] = 0xFF;
    sha256(seed2, WABISABI_SCALAR_SIZE + 1, prove_rand);

    wabisabi_prove(out_req->proofs, &prove_transcript, knowledge, WABISABI_CREDENTIAL_COUNT, prove_rand,
                   WABISABI_SCALAR_SIZE);

    /* Save post-challenge transcript state for issuer param verification.
   * C# stores the transcript after Prove() completes (post-challenge state),
   * and uses that same advanced transcript for HandleResponse/Verify. */
    wabisabi_transcript_clone(&out_val->transcript, &prove_transcript);

    out_val->n_requested = WABISABI_CREDENTIAL_COUNT;
}

/* Internal helper: build a real request */
static void
internal_create_real(wabisabi_client_state_t* c, const int64_t* amounts_to_request, int n_amounts,
                     const wabisabi_credential_t* credentials_to_present, int n_present, const uint8_t* random_bytes,
                     wabisabi_real_request_t* out_req, wabisabi_response_validation_t* out_val) {
    /* Pad amounts to k */
    int64_t amounts[WABISABI_CREDENTIAL_COUNT] = {0};
    for (int i = 0; i < n_amounts && i < WABISABI_CREDENTIAL_COUNT; i++) {
        amounts[i] = amounts_to_request[i];
    }

    wabisabi_knowledge_t all_knowledge[WABISABI_CREDENTIAL_COUNT * 2 + 1];
    int n_knowledge = 0;

    /* Generate randomization scalars and presentations */
    wabisabi_scalar_t z_scalars[WABISABI_CREDENTIAL_COUNT];
    int64_t total_presented = 0;

    for (int i = 0; i < n_present; i++) {
        /* Derive z */
        uint8_t seed[WABISABI_SCALAR_SIZE + 1];
        memcpy(seed, random_bytes, WABISABI_SCALAR_SIZE);
        seed[WABISABI_SCALAR_SIZE] = (uint8_t)i;
        uint8_t z_bytes[WABISABI_SCALAR_SIZE];
        sha256(seed, WABISABI_SCALAR_SIZE + 1, z_bytes);
        while (!secp256k1_ec_seckey_verify(WABISABI_CTX, z_bytes)) {
            sha256(z_bytes, WABISABI_SCALAR_SIZE, z_bytes);
        }
        memcpy(z_scalars[i].data, z_bytes, WABISABI_SCALAR_SIZE);

        out_req->presented[i] =
            wabisabi_credential_present(&credentials_to_present[i].mac, credentials_to_present[i].value,
                                        &credentials_to_present[i].randomness, &z_scalars[i]);

        all_knowledge[n_knowledge++] = wabisabi_show_credential_knowledge(
            &out_req->presented[i], &z_scalars[i], &credentials_to_present[i].mac, credentials_to_present[i].value,
            &credentials_to_present[i].randomness, &c->iparams);

        total_presented += credentials_to_present[i].value;
    }

    /* Generate range proofs for requested credentials */
    int64_t total_requested = 0;
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int64_t val = amounts[i];
        total_requested += val;

        /* Derive randomness for issuance */
        uint8_t seed[WABISABI_SCALAR_SIZE + 1];
        memcpy(seed, random_bytes, WABISABI_SCALAR_SIZE);
        seed[WABISABI_SCALAR_SIZE] = (uint8_t)(128 + i);
        uint8_t r_bytes[WABISABI_SCALAR_SIZE];
        sha256(seed, WABISABI_SCALAR_SIZE + 1, r_bytes);
        while (!secp256k1_ec_seckey_verify(WABISABI_CTX, r_bytes)) {
            sha256(r_bytes, WABISABI_SCALAR_SIZE, r_bytes);
        }

        wabisabi_scalar_t randomness;
        memcpy(randomness.data, r_bytes, WABISABI_SCALAR_SIZE);

        wabisabi_scalar_t val_scalar;
        memset(val_scalar.data, 0, WABISABI_SCALAR_SIZE);
        uint64_t uval = (uint64_t)val;
        for (int b = 0; b < 8; b++) {
            val_scalar.data[31 - b] = (uint8_t)(uval >> (8 * b));
        }

        wabisabi_ge_t ma;
        wabisabi_pedersen_commit(&ma, &val_scalar, &randomness);

        /* Bit randomness seed */
        uint8_t bit_seed[WABISABI_SCALAR_SIZE + 1];
        memcpy(bit_seed, r_bytes, WABISABI_SCALAR_SIZE);
        bit_seed[WABISABI_SCALAR_SIZE] = 0xBB;
        uint8_t bit_rand[WABISABI_SCALAR_SIZE];
        sha256(bit_seed, WABISABI_SCALAR_SIZE + 1, bit_rand);

        wabisabi_range_proof_t rp = wabisabi_range_proof_knowledge(&val_scalar, &randomness, c->range_proof_width,
                                                                   bit_rand, WABISABI_SCALAR_SIZE);

        /* Fill issuance request */
        out_req->requested[i].ma = ma;
        out_req->requested[i].n_bit_commitments = rp.width;
        memcpy(out_req->requested[i].bit_commitments, rp.bit_commitments, rp.width * sizeof(wabisabi_ge_t));

        all_knowledge[n_knowledge++] = rp.knowledge;

        out_val->requested[i].value = val;
        out_val->requested[i].randomness = randomness;
        out_val->requested[i].ma = ma;
    }

    /* Balance proof */
    {
        /* sum_z = sum of all z scalars */
        wabisabi_scalar_t sum_z = WABISABI_SCALAR_ZERO;
        for (int i = 0; i < n_present; i++) {
            wabisabi_scalar_add(&sum_z, &sum_z, &z_scalars[i]);
        }

        /* cr = sum of presented credential randomness */
        wabisabi_scalar_t cr = WABISABI_SCALAR_ZERO;
        for (int i = 0; i < n_present; i++) {
            wabisabi_scalar_add(&cr, &cr, &credentials_to_present[i].randomness);
        }

        /* r_new = sum of new credential randomness */
        wabisabi_scalar_t r_new = WABISABI_SCALAR_ZERO;
        for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
            wabisabi_scalar_add(&r_new, &r_new, &out_val->requested[i].randomness);
        }

        /* delta_r = cr - r_new */
        wabisabi_scalar_t neg_r_new;
        wabisabi_scalar_negate(&neg_r_new, &r_new);
        wabisabi_scalar_t delta_r;
        wabisabi_scalar_add(&delta_r, &cr, &neg_r_new);

        all_knowledge[n_knowledge++] = wabisabi_balance_proof_knowledge(&sum_z, &delta_r);
    }

    out_req->delta = total_requested - total_presented;
    out_req->n_proofs = n_knowledge;

    /* Build and advance the prove transcript */
    wabisabi_transcript_t prove_transcript;
    build_transcript(&prove_transcript, 0);

    uint8_t prove_rand[WABISABI_SCALAR_SIZE];
    uint8_t seed2[WABISABI_SCALAR_SIZE + 1];
    memcpy(seed2, random_bytes, WABISABI_SCALAR_SIZE);
    seed2[WABISABI_SCALAR_SIZE] = 0xAA;
    sha256(seed2, WABISABI_SCALAR_SIZE + 1, prove_rand);

    wabisabi_prove(out_req->proofs, &prove_transcript, all_knowledge, n_knowledge, prove_rand, WABISABI_SCALAR_SIZE);

    /* Save post-challenge transcript for issuer param verification */
    wabisabi_transcript_clone(&out_val->transcript, &prove_transcript);

    out_val->n_requested = WABISABI_CREDENTIAL_COUNT;
}

void
wabisabi_client_state_create_present_request(wabisabi_client_state_t* c,
                                             const wabisabi_credential_t* credentials_to_present, int n_present,
                                             const uint8_t* random_bytes, wabisabi_real_request_t* out_req,
                                             wabisabi_response_validation_t* out_val) {
    internal_create_real(c, NULL, 0, credentials_to_present, n_present, random_bytes, out_req, out_val);
}

void
wabisabi_client_state_create_real_request(wabisabi_client_state_t* c, const int64_t* amounts_to_request, int n_amounts,
                                          const wabisabi_credential_t* credentials_to_present, int n_present,
                                          const uint8_t* random_bytes, wabisabi_real_request_t* out_req,
                                          wabisabi_response_validation_t* out_val) {
    internal_create_real(c, amounts_to_request, n_amounts, credentials_to_present, n_present, random_bytes, out_req,
                         out_val);
}

wabisabi_error_t
wabisabi_client_state_handle_response(wabisabi_client_state_t* c, const wabisabi_response_t* response,
                                      const wabisabi_response_validation_t* val,
                                      wabisabi_credential_t out_credentials[WABISABI_CREDENTIAL_COUNT]) {
    /* Verify issuer parameter proofs */
    wabisabi_statement_t statements[WABISABI_CREDENTIAL_COUNT];
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        statements[i] = wabisabi_issuer_params_statement(&c->iparams, &response->issued[i], &val->requested[i].ma);
    }

    /* Advance our copy of the transcript (same state as during proving) */
    wabisabi_transcript_t verify_transcript;
    wabisabi_transcript_clone(&verify_transcript, &val->transcript);

    if (!wabisabi_verify(&verify_transcript, statements, WABISABI_CREDENTIAL_COUNT, response->proofs,
                         WABISABI_CREDENTIAL_COUNT)) {
        return WABISABI_ERR_INVALID_PROOF;
    }

    /* Build credentials from issued MACs */
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        out_credentials[i].value = val->requested[i].value;
        out_credentials[i].randomness = val->requested[i].randomness;
        out_credentials[i].mac = response->issued[i];
    }

    return WABISABI_OK;
}
