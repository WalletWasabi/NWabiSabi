/* Transcript — matches C# Transcript.cs and SyntheticSecretNonceProvider.cs */
#include "transcript.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WABISABI_PROTOCOL "WabiSabi_v1.0"

static const uint8_t TAG_STATEMENT[] = "statement";
static const uint8_t TAG_CHALLENGE[] = "challenge";
static const uint8_t TAG_NONCE[] = "nonce-commitment";
static const uint8_t TAG_DOMAIN_SEP[] = "domain-separator";

/* Helpers matching C# AddMessage / AddMessages */

static void
write_le_u32(uint8_t* b, uint32_t v) {
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

/* meta-AD(label) + meta-AD(LE32(len)) + AD(data) */
static void
add_message(strobe128_t* s, const uint8_t* label, size_t label_len, const uint8_t* data, size_t data_len) {
    strobe128_meta_ad(s, label, label_len, 0);
    uint8_t len_bytes[4];
    write_le_u32(len_bytes, (uint32_t)data_len);
    strobe128_meta_ad(s, len_bytes, 4, 1);
    strobe128_ad(s, data, data_len, 0);
}

/* add_messages: meta-AD(label) + meta-AD(LE32(count)) + for each i:
 * add_message(LE32(i), data[i])
 */
static void
add_messages_ge(strobe128_t* s, const uint8_t* label, size_t label_len, const wabisabi_ge_t* elems, size_t n) {
    strobe128_meta_ad(s, label, label_len, 0);
    uint8_t cnt[4];
    write_le_u32(cnt, (uint32_t)n);
    strobe128_meta_ad(s, cnt, 4, 1);

    for (size_t i = 0; i < n; i++) {
        uint8_t idx[4];
        write_le_u32(idx, (uint32_t)i);
        uint8_t ge_bytes[WABISABI_GE_SIZE];
        wabisabi_ge_serialize(ge_bytes, &elems[i]);
        add_message(s, idx, 4, ge_bytes, WABISABI_GE_SIZE);
    }
}

void
wabisabi_transcript_init(wabisabi_transcript_t* t, const uint8_t* label, size_t label_len) {
    strobe128_init(&t->strobe, WABISABI_PROTOCOL);
    add_message(&t->strobe, TAG_DOMAIN_SEP, sizeof(TAG_DOMAIN_SEP) - 1, label, label_len);
}

void
wabisabi_transcript_clone(wabisabi_transcript_t* dst, const wabisabi_transcript_t* src) {
    strobe128_clone(&dst->strobe, &src->strobe);
}

void
wabisabi_transcript_commit_statement(wabisabi_transcript_t* t, const wabisabi_ge_t* public_points, size_t n_public,
                                     const wabisabi_ge_t* generators, size_t n_gen) {
    /* Combine public_points and generators into one sequence, matching C#:
   *   statement.PublicPoints ++ statement.Generators
   */
    strobe128_t* s = &t->strobe;

    strobe128_meta_ad(s, TAG_STATEMENT, sizeof(TAG_STATEMENT) - 1, 0);
    uint32_t total = (uint32_t)(n_public + n_gen);
    uint8_t cnt[4];
    write_le_u32(cnt, total);
    strobe128_meta_ad(s, cnt, 4, 1);

    for (size_t i = 0; i < n_public + n_gen; i++) {
        const wabisabi_ge_t* ge = (i < n_public) ? &public_points[i] : &generators[i - n_public];
        uint8_t idx[4];
        write_le_u32(idx, (uint32_t)i);
        uint8_t ge_bytes[WABISABI_GE_SIZE];
        wabisabi_ge_serialize(ge_bytes, ge);
        add_message(s, idx, 4, ge_bytes, WABISABI_GE_SIZE);
    }
}

void
wabisabi_transcript_commit_nonces(wabisabi_transcript_t* t, const wabisabi_ge_t* nonces, size_t n) {
    add_messages_ge(&t->strobe, TAG_NONCE, sizeof(TAG_NONCE) - 1, nonces, n);
}

void
wabisabi_transcript_challenge(wabisabi_scalar_t* out, wabisabi_transcript_t* t) {
    uint8_t buf[WABISABI_SCALAR_SIZE];
    do {
        strobe128_meta_ad(&t->strobe, TAG_CHALLENGE, sizeof(TAG_CHALLENGE) - 1, 0);
        strobe128_prf(&t->strobe, buf, WABISABI_SCALAR_SIZE, 0);
        memcpy(out->data, buf, WABISABI_SCALAR_SIZE);
        /* Re-draw if overflow (value >= n) — check by trying to use as seckey */
    } while (!secp256k1_ec_seckey_verify(WABISABI_CTX, out->data) && !wabisabi_scalar_is_zero(out));
    /* Note: wabisabi_scalar_is_zero is checked separately; zero is astronomically
   * unlikely from a PRF but must never be a challenge per the proof system. */
}

void
wabisabi_nonce_provider_init(wabisabi_nonce_provider_t* p, const wabisabi_transcript_t* t,
                             const wabisabi_scalar_t* secrets, int n, const uint8_t* extra_random, size_t rnd_len) {
    strobe128_clone(&p->strobe, &t->strobe);
    p->n_secrets = n;

    /* KEY each secret */
    for (int i = 0; i < n; i++) {
        strobe128_key(&p->strobe, secrets[i].data, WABISABI_SCALAR_SIZE, 0);
    }
    /* KEY the random bytes */
    strobe128_key(&p->strobe, extra_random, rnd_len, 0);
}

void
wabisabi_nonce_provider_next(wabisabi_scalar_t* out, wabisabi_nonce_provider_t* p) {
    uint8_t buf[WABISABI_SCALAR_SIZE];
    do {
        strobe128_prf(&p->strobe, buf, WABISABI_SCALAR_SIZE, 0);
        memcpy(out->data, buf, WABISABI_SCALAR_SIZE);
    } while (!secp256k1_ec_seckey_verify(WABISABI_CTX, out->data) && !wabisabi_scalar_is_zero(out));
}

void
wabisabi_nonce_provider_fill(wabisabi_scalar_t* out, int n, wabisabi_nonce_provider_t* p) {
    for (int i = 0; i < n; i++) {
        wabisabi_nonce_provider_next(&out[i], p);
    }
}
