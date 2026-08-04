/*
 * ownership_proof.c - SLIP-0019 Ownership Proof Implementation
 *
 * Uses libsecp256k1 for ECDSA and Schnorr signatures.
 * Uses OpenSSL or similar for SHA256 and HMAC-SHA256.
 */

#include "ownership_proof.h"
#include <string.h>
#include <stdio.h>

/* Use libsecp256k1 for EC operations */
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

/* SHA-256 is shared with the rest of the library (src/sha256.c); this module
 * only adds HMAC-SHA256 and RIPEMD-160 on top of it. sha256_t + sha256_init/
 * update/final and the one-shot sha256() come from sha256.h. */
#include "sha256.h"

/* HMAC-SHA256 */
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32]) {
    uint8_t k_pad[64];
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t inner_hash[32];
    sha256_t ctx;

    /* If key > 64 bytes, hash it first */
    if (key_len > 64) {
        sha256(key, key_len, k_pad);
        key = k_pad;
        key_len = 32;
    }

    /* Prepare padded keys */
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner hash: H(K XOR ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    /* Outer hash: H(K XOR opad || inner_hash) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out);
}

/* Global secp256k1 context */
static secp256k1_context *secp_ctx = NULL;

static secp256k1_context *get_secp_context(void) {
    if (secp_ctx == NULL) {
        secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return secp_ctx;
}

/* Utility functions */

op_error_t varint_write(uint64_t value, uint8_t *out, size_t *out_len) {
    if (!out || !out_len) return OP_ERROR_INVALID_INPUT;

    if (value < 0xfd) {
        if (*out_len < 1) return OP_ERROR_BUFFER_TOO_SMALL;
        out[0] = (uint8_t)value;
        *out_len = 1;
    } else if (value <= 0xffff) {
        if (*out_len < 3) return OP_ERROR_BUFFER_TOO_SMALL;
        out[0] = 0xfd;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        *out_len = 3;
    } else if (value <= 0xffffffff) {
        if (*out_len < 5) return OP_ERROR_BUFFER_TOO_SMALL;
        out[0] = 0xfe;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        out[3] = (uint8_t)((value >> 16) & 0xff);
        out[4] = (uint8_t)((value >> 24) & 0xff);
        *out_len = 5;
    } else {
        if (*out_len < 9) return OP_ERROR_BUFFER_TOO_SMALL;
        out[0] = 0xff;
        for (int i = 0; i < 8; i++) {
            out[1 + i] = (uint8_t)((value >> (i * 8)) & 0xff);
        }
        *out_len = 9;
    }
    return OP_SUCCESS;
}

op_error_t varint_read(const uint8_t *data, size_t data_len, uint64_t *value, size_t *consumed) {
    if (!data || !value || !consumed || data_len == 0) return OP_ERROR_INVALID_INPUT;

    if (data[0] < 0xfd) {
        *value = data[0];
        *consumed = 1;
    } else if (data[0] == 0xfd) {
        if (data_len < 3) return OP_ERROR_INVALID_FORMAT;
        *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8);
        *consumed = 3;
    } else if (data[0] == 0xfe) {
        if (data_len < 5) return OP_ERROR_INVALID_FORMAT;
        *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8) |
                 ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24);
        *consumed = 5;
    } else {
        if (data_len < 9) return OP_ERROR_INVALID_FORMAT;
        *value = 0;
        for (int i = 0; i < 8; i++) {
            *value |= ((uint64_t)data[1 + i] << (i * 8));
        }
        *consumed = 9;
    }
    return OP_SUCCESS;
}

void bytes_to_hex(const uint8_t *data, size_t data_len, char *hex) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < data_len; i++) {
        hex[i * 2] = hex_chars[(data[i] >> 4) & 0xf];
        hex[i * 2 + 1] = hex_chars[data[i] & 0xf];
    }
    hex[data_len * 2] = '\0';
}

op_error_t hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len) {
    if (!hex || !out || !out_len) return OP_ERROR_INVALID_INPUT;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return OP_ERROR_INVALID_FORMAT;

    size_t byte_len = hex_len / 2;
    if (*out_len < byte_len) return OP_ERROR_BUFFER_TOO_SMALL;

    for (size_t i = 0; i < byte_len; i++) {
        uint8_t hi, lo;
        char c = hex[i * 2];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return OP_ERROR_INVALID_FORMAT;

        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return OP_ERROR_INVALID_FORMAT;

        out[i] = (hi << 4) | lo;
    }
    *out_len = byte_len;
    return OP_SUCCESS;
}

/* Ownership identifier */

op_error_t ownership_id_compute(
    const uint8_t identification_key[32],
    const script_pubkey_t *script_pubkey,
    ownership_id_t *out) {

    if (!identification_key || !script_pubkey || !out) return OP_ERROR_INVALID_INPUT;

    hmac_sha256(identification_key, 32, script_pubkey->data, script_pubkey->length, out->bytes);
    return OP_SUCCESS;
}

/* Proof body */

op_error_t proof_body_init(
    proof_body_t *body,
    uint8_t flags,
    const ownership_id_t *identifiers,
    size_t num_identifiers) {

    if (!body) return OP_ERROR_INVALID_INPUT;
    if (num_identifiers > MAX_OWNERSHIP_IDENTIFIERS) return OP_ERROR_INVALID_INPUT;

    body->flags = flags;
    body->num_identifiers = num_identifiers;

    if (identifiers && num_identifiers > 0) {
        memcpy(body->identifiers, identifiers, num_identifiers * sizeof(ownership_id_t));
    }
    return OP_SUCCESS;
}

op_error_t proof_body_serialize(
    const proof_body_t *body,
    uint8_t *out,
    size_t *out_len) {

    if (!body || !out || !out_len) return OP_ERROR_INVALID_INPUT;

    size_t required = VERSION_MAGIC_LENGTH + 1; /* magic + flags */
    size_t varint_space = 9; /* max varint size */

    /* Calculate required size */
    required += varint_space + (body->num_identifiers * OWNERSHIP_ID_LENGTH);

    if (*out_len < required) return OP_ERROR_BUFFER_TOO_SMALL;

    size_t offset = 0;

    /* Write version magic */
    memcpy(out, VERSION_MAGIC, VERSION_MAGIC_LENGTH);
    offset += VERSION_MAGIC_LENGTH;

    /* Write flags */
    out[offset++] = body->flags;

    /* Write number of identifiers as varint */
    size_t vi_len = *out_len - offset;
    op_error_t err = varint_write(body->num_identifiers, out + offset, &vi_len);
    if (err != OP_SUCCESS) return err;
    offset += vi_len;

    /* Write identifiers */
    for (size_t i = 0; i < body->num_identifiers; i++) {
        memcpy(out + offset, body->identifiers[i].bytes, OWNERSHIP_ID_LENGTH);
        offset += OWNERSHIP_ID_LENGTH;
    }

    *out_len = offset;
    return OP_SUCCESS;
}

op_error_t proof_body_deserialize(
    const uint8_t *data,
    size_t data_len,
    proof_body_t *body,
    size_t *consumed) {

    if (!data || !body || !consumed) return OP_ERROR_INVALID_INPUT;
    if (data_len < VERSION_MAGIC_LENGTH + 1) return OP_ERROR_INVALID_FORMAT;

    size_t offset = 0;

    /* Check version magic */
    if (memcmp(data, VERSION_MAGIC, VERSION_MAGIC_LENGTH) != 0) {
        return OP_ERROR_INVALID_VERSION_MAGIC;
    }
    offset += VERSION_MAGIC_LENGTH;

    /* Read flags */
    body->flags = data[offset++];

    /* Read number of identifiers */
    uint64_t num_ids;
    size_t vi_consumed;
    op_error_t err = varint_read(data + offset, data_len - offset, &num_ids, &vi_consumed);
    if (err != OP_SUCCESS) return err;
    offset += vi_consumed;

    if (num_ids > MAX_OWNERSHIP_IDENTIFIERS) return OP_ERROR_INVALID_FORMAT;
    body->num_identifiers = (size_t)num_ids;

    /* Read identifiers */
    size_t ids_size = body->num_identifiers * OWNERSHIP_ID_LENGTH;
    if (offset + ids_size > data_len) return OP_ERROR_INVALID_FORMAT;

    for (size_t i = 0; i < body->num_identifiers; i++) {
        memcpy(body->identifiers[i].bytes, data + offset, OWNERSHIP_ID_LENGTH);
        offset += OWNERSHIP_ID_LENGTH;
    }

    *consumed = offset;
    return OP_SUCCESS;
}

op_error_t proof_body_signature_hash(
    const proof_body_t *body,
    const script_pubkey_t *script_pubkey,
    const uint8_t *commitment_data,
    size_t commitment_len,
    uint8_t hash_out[SHA256_HASH_LENGTH]) {

    if (!body || !script_pubkey || !hash_out) return OP_ERROR_INVALID_INPUT;
    if (commitment_len > 0 && !commitment_data) return OP_ERROR_INVALID_INPUT;

    /* Serialize proof body */
    uint8_t body_bytes[4096];
    size_t body_len = sizeof(body_bytes);
    op_error_t err = proof_body_serialize(body, body_bytes, &body_len);
    if (err != OP_SUCCESS) return err;

    /* Build proof footer */
    uint8_t footer[4096];
    size_t footer_offset = 0;

    /* varint(script_len) || script */
    size_t vi_len = sizeof(footer);
    err = varint_write(script_pubkey->length, footer, &vi_len);
    if (err != OP_SUCCESS) return err;
    footer_offset += vi_len;

    memcpy(footer + footer_offset, script_pubkey->data, script_pubkey->length);
    footer_offset += script_pubkey->length;

    /* varint(commitment_len) || commitment */
    vi_len = sizeof(footer) - footer_offset;
    err = varint_write(commitment_len, footer + footer_offset, &vi_len);
    if (err != OP_SUCCESS) return err;
    footer_offset += vi_len;

    if (commitment_len > 0) {
        memcpy(footer + footer_offset, commitment_data, commitment_len);
        footer_offset += commitment_len;
    }

    /* Hash body || footer */
    sha256_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, body_bytes, body_len);
    sha256_update(&ctx, footer, footer_offset);
    sha256_final(&ctx, hash_out);

    return OP_SUCCESS;
}

/* BIP-322 signature */

op_error_t bip322_signature_serialize(
    const bip322_signature_t *sig,
    uint8_t *out,
    size_t *out_len) {

    if (!sig || !out || !out_len) return OP_ERROR_INVALID_INPUT;

    size_t offset = 0;

    /* Write scriptSig length as varint */
    size_t vi_len = *out_len;
    op_error_t err = varint_write(sig->script_sig_length, out, &vi_len);
    if (err != OP_SUCCESS) return err;
    offset += vi_len;

    /* Write scriptSig */
    if (sig->script_sig_length > 0) {
        if (offset + sig->script_sig_length > *out_len) return OP_ERROR_BUFFER_TOO_SMALL;
        memcpy(out + offset, sig->script_sig, sig->script_sig_length);
        offset += sig->script_sig_length;
    }

    /* Write witness stack count as varint */
    vi_len = *out_len - offset;
    err = varint_write(sig->witness.num_items, out + offset, &vi_len);
    if (err != OP_SUCCESS) return err;
    offset += vi_len;

    /* Write witness items */
    for (size_t i = 0; i < sig->witness.num_items; i++) {
        /* Item length as varint */
        vi_len = *out_len - offset;
        err = varint_write(sig->witness.items[i].length, out + offset, &vi_len);
        if (err != OP_SUCCESS) return err;
        offset += vi_len;

        /* Item data */
        if (sig->witness.items[i].length > 0) {
            if (offset + sig->witness.items[i].length > *out_len) return OP_ERROR_BUFFER_TOO_SMALL;
            memcpy(out + offset, sig->witness.items[i].data, sig->witness.items[i].length);
            offset += sig->witness.items[i].length;
        }
    }

    *out_len = offset;
    return OP_SUCCESS;
}

op_error_t bip322_signature_deserialize(
    const uint8_t *data,
    size_t data_len,
    bip322_signature_t *sig,
    size_t *consumed) {

    if (!data || !sig || !consumed) return OP_ERROR_INVALID_INPUT;

    size_t offset = 0;

    /* Read scriptSig length */
    uint64_t script_len;
    size_t vi_consumed;
    op_error_t err = varint_read(data, data_len, &script_len, &vi_consumed);
    if (err != OP_SUCCESS) return err;
    offset += vi_consumed;

    if (script_len > MAX_SCRIPT_LENGTH) return OP_ERROR_INVALID_FORMAT;
    sig->script_sig_length = (size_t)script_len;

    /* Read scriptSig */
    if (script_len > 0) {
        if (offset + script_len > data_len) return OP_ERROR_INVALID_FORMAT;
        memcpy(sig->script_sig, data + offset, script_len);
        offset += script_len;
    }

    /* Read witness stack count */
    uint64_t num_items;
    err = varint_read(data + offset, data_len - offset, &num_items, &vi_consumed);
    if (err != OP_SUCCESS) return err;
    offset += vi_consumed;

    if (num_items > MAX_WITNESS_ITEMS) return OP_ERROR_INVALID_FORMAT;
    sig->witness.num_items = (size_t)num_items;

    /* Read witness items */
    for (size_t i = 0; i < sig->witness.num_items; i++) {
        uint64_t item_len;
        err = varint_read(data + offset, data_len - offset, &item_len, &vi_consumed);
        if (err != OP_SUCCESS) return err;
        offset += vi_consumed;

        if (item_len > MAX_WITNESS_ITEM_LENGTH) return OP_ERROR_INVALID_FORMAT;
        sig->witness.items[i].length = (size_t)item_len;

        if (item_len > 0) {
            if (offset + item_len > data_len) return OP_ERROR_INVALID_FORMAT;
            memcpy(sig->witness.items[i].data, data + offset, item_len);
            offset += item_len;
        }
    }

    *consumed = offset;
    return OP_SUCCESS;
}

/* Script type detection */

script_type_t script_pubkey_get_type(const script_pubkey_t *script_pubkey) {
    if (!script_pubkey || script_pubkey->length == 0) return SCRIPT_TYPE_UNKNOWN;

    /* P2WPKH: OP_0 <20-byte-key-hash> (22 bytes total) */
    if (script_pubkey->length == 22 &&
        script_pubkey->data[0] == 0x00 &&
        script_pubkey->data[1] == 0x14) {
        return SCRIPT_TYPE_P2WPKH;
    }

    /* P2TR: OP_1 <32-byte-x-only-pubkey> (34 bytes total) */
    if (script_pubkey->length == 34 &&
        script_pubkey->data[0] == 0x51 &&
        script_pubkey->data[1] == 0x20) {
        return SCRIPT_TYPE_P2TR;
    }

    return SCRIPT_TYPE_UNKNOWN;
}

/* Forward declaration for ripemd160 */
static void ripemd160(const uint8_t *data, size_t len, uint8_t out[20]);

/* Derive scriptPubKey from private key */
op_error_t script_pubkey_from_privkey(
    const uint8_t privkey[32],
    script_type_t script_type,
    script_pubkey_t *script_pubkey) {

    if (!privkey || !script_pubkey) return OP_ERROR_INVALID_INPUT;
    if (script_type != SCRIPT_TYPE_P2WPKH && script_type != SCRIPT_TYPE_P2TR) {
        return OP_ERROR_UNSUPPORTED_SCRIPT_TYPE;
    }

    secp256k1_context *ctx = get_secp_context();
    if (!ctx) return OP_ERROR_CRYPTO_FAILED;

    if (script_type == SCRIPT_TYPE_P2WPKH) {
        /* Get compressed public key */
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        uint8_t pubkey_bytes[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

        /* hash160 = RIPEMD160(SHA256(pubkey)) */
        uint8_t sha_hash[32];
        sha256(pubkey_bytes, 33, sha_hash);

        uint8_t hash160[20];
        ripemd160(sha_hash, 32, hash160);

        /* P2WPKH script: OP_0 <20-byte-hash> */
        script_pubkey->length = 22;
        script_pubkey->data[0] = 0x00;  /* OP_0 */
        script_pubkey->data[1] = 0x14;  /* Push 20 bytes */
        memcpy(script_pubkey->data + 2, hash160, 20);

    } else if (script_type == SCRIPT_TYPE_P2TR) {
        /* Create keypair */
        secp256k1_keypair keypair;
        if (!secp256k1_keypair_create(ctx, &keypair, privkey)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        /* Get x-only pubkey */
        secp256k1_xonly_pubkey xonly_pubkey;
        if (!secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        uint8_t xonly_bytes[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, xonly_bytes, &xonly_pubkey)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        /* Compute BIP86 tweak = tagged_hash("TapTweak", xonly_pubkey) */
        uint8_t tag_hash[32];
        sha256((const uint8_t*)"TapTweak", 8, tag_hash);

        sha256_t hash_ctx;
        sha256_init(&hash_ctx);
        sha256_update(&hash_ctx, tag_hash, 32);
        sha256_update(&hash_ctx, tag_hash, 32);
        sha256_update(&hash_ctx, xonly_bytes, 32);
        uint8_t tweak[32];
        sha256_final(&hash_ctx, tweak);

        /* Apply tweak to get output key */
        secp256k1_pubkey tweaked_pubkey;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pubkey, &xonly_pubkey, tweak)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        /* Convert tweaked pubkey back to x-only */
        secp256k1_xonly_pubkey tweaked_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pubkey)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        uint8_t output_key[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, output_key, &tweaked_xonly)) {
            return OP_ERROR_CRYPTO_FAILED;
        }

        /* P2TR script: OP_1 <32-byte-x-only-pubkey> */
        script_pubkey->length = 34;
        script_pubkey->data[0] = 0x51;  /* OP_1 */
        script_pubkey->data[1] = 0x20;  /* Push 32 bytes */
        memcpy(script_pubkey->data + 2, output_key, 32);
    }

    return OP_SUCCESS;
}

/* RIPEMD-160 implementation (needed for P2WPKH verification) */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define RMD_F(x, y, z) ((x) ^ (y) ^ (z))
#define RMD_G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RMD_H(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD_I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RMD_J(x, y, z) ((x) ^ ((y) | ~(z)))

#define RMD_FF(a, b, c, d, e, x, s) { \
    (a) += RMD_F((b), (c), (d)) + (x); \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_GG(a, b, c, d, e, x, s) { \
    (a) += RMD_G((b), (c), (d)) + (x) + 0x5a827999UL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_HH(a, b, c, d, e, x, s) { \
    (a) += RMD_H((b), (c), (d)) + (x) + 0x6ed9eba1UL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_II(a, b, c, d, e, x, s) { \
    (a) += RMD_I((b), (c), (d)) + (x) + 0x8f1bbcdcUL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_JJ(a, b, c, d, e, x, s) { \
    (a) += RMD_J((b), (c), (d)) + (x) + 0xa953fd4eUL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_FFF(a, b, c, d, e, x, s) { \
    (a) += RMD_F((b), (c), (d)) + (x); \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_GGG(a, b, c, d, e, x, s) { \
    (a) += RMD_G((b), (c), (d)) + (x) + 0x7a6d76e9UL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_HHH(a, b, c, d, e, x, s) { \
    (a) += RMD_H((b), (c), (d)) + (x) + 0x6d703ef3UL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_III(a, b, c, d, e, x, s) { \
    (a) += RMD_I((b), (c), (d)) + (x) + 0x5c4dd124UL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}
#define RMD_JJJ(a, b, c, d, e, x, s) { \
    (a) += RMD_J((b), (c), (d)) + (x) + 0x50a28be6UL; \
    (a) = ROTL32((a), (s)) + (e); \
    (c) = ROTL32((c), 10); \
}

static void ripemd160_transform(uint32_t *state, const uint8_t *block) {
    uint32_t a, b, c, d, e, aa, bb, cc, dd, ee, t;
    uint32_t x[16];

    for (int i = 0; i < 16; i++) {
        x[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }

    a = aa = state[0];
    b = bb = state[1];
    c = cc = state[2];
    d = dd = state[3];
    e = ee = state[4];

    /* Round 1 - left */
    RMD_FF(a, b, c, d, e, x[ 0], 11); RMD_FF(e, a, b, c, d, x[ 1], 14);
    RMD_FF(d, e, a, b, c, x[ 2], 15); RMD_FF(c, d, e, a, b, x[ 3], 12);
    RMD_FF(b, c, d, e, a, x[ 4],  5); RMD_FF(a, b, c, d, e, x[ 5],  8);
    RMD_FF(e, a, b, c, d, x[ 6],  7); RMD_FF(d, e, a, b, c, x[ 7],  9);
    RMD_FF(c, d, e, a, b, x[ 8], 11); RMD_FF(b, c, d, e, a, x[ 9], 13);
    RMD_FF(a, b, c, d, e, x[10], 14); RMD_FF(e, a, b, c, d, x[11], 15);
    RMD_FF(d, e, a, b, c, x[12],  6); RMD_FF(c, d, e, a, b, x[13],  7);
    RMD_FF(b, c, d, e, a, x[14],  9); RMD_FF(a, b, c, d, e, x[15],  8);

    /* Round 2 - left */
    RMD_GG(e, a, b, c, d, x[ 7],  7); RMD_GG(d, e, a, b, c, x[ 4],  6);
    RMD_GG(c, d, e, a, b, x[13],  8); RMD_GG(b, c, d, e, a, x[ 1], 13);
    RMD_GG(a, b, c, d, e, x[10], 11); RMD_GG(e, a, b, c, d, x[ 6],  9);
    RMD_GG(d, e, a, b, c, x[15],  7); RMD_GG(c, d, e, a, b, x[ 3], 15);
    RMD_GG(b, c, d, e, a, x[12],  7); RMD_GG(a, b, c, d, e, x[ 0], 12);
    RMD_GG(e, a, b, c, d, x[ 9], 15); RMD_GG(d, e, a, b, c, x[ 5],  9);
    RMD_GG(c, d, e, a, b, x[ 2], 11); RMD_GG(b, c, d, e, a, x[14],  7);
    RMD_GG(a, b, c, d, e, x[11], 13); RMD_GG(e, a, b, c, d, x[ 8], 12);

    /* Round 3 - left */
    RMD_HH(d, e, a, b, c, x[ 3], 11); RMD_HH(c, d, e, a, b, x[10], 13);
    RMD_HH(b, c, d, e, a, x[14],  6); RMD_HH(a, b, c, d, e, x[ 4],  7);
    RMD_HH(e, a, b, c, d, x[ 9], 14); RMD_HH(d, e, a, b, c, x[15],  9);
    RMD_HH(c, d, e, a, b, x[ 8], 13); RMD_HH(b, c, d, e, a, x[ 1], 15);
    RMD_HH(a, b, c, d, e, x[ 2], 14); RMD_HH(e, a, b, c, d, x[ 7],  8);
    RMD_HH(d, e, a, b, c, x[ 0], 13); RMD_HH(c, d, e, a, b, x[ 6],  6);
    RMD_HH(b, c, d, e, a, x[13],  5); RMD_HH(a, b, c, d, e, x[11], 12);
    RMD_HH(e, a, b, c, d, x[ 5],  7); RMD_HH(d, e, a, b, c, x[12],  5);

    /* Round 4 - left */
    RMD_II(c, d, e, a, b, x[ 1], 11); RMD_II(b, c, d, e, a, x[ 9], 12);
    RMD_II(a, b, c, d, e, x[11], 14); RMD_II(e, a, b, c, d, x[10], 15);
    RMD_II(d, e, a, b, c, x[ 0], 14); RMD_II(c, d, e, a, b, x[ 8], 15);
    RMD_II(b, c, d, e, a, x[12],  9); RMD_II(a, b, c, d, e, x[ 4],  8);
    RMD_II(e, a, b, c, d, x[13],  9); RMD_II(d, e, a, b, c, x[ 3], 14);
    RMD_II(c, d, e, a, b, x[ 7],  5); RMD_II(b, c, d, e, a, x[15],  6);
    RMD_II(a, b, c, d, e, x[14],  8); RMD_II(e, a, b, c, d, x[ 5],  6);
    RMD_II(d, e, a, b, c, x[ 6],  5); RMD_II(c, d, e, a, b, x[ 2], 12);

    /* Round 5 - left */
    RMD_JJ(b, c, d, e, a, x[ 4],  9); RMD_JJ(a, b, c, d, e, x[ 0], 15);
    RMD_JJ(e, a, b, c, d, x[ 5],  5); RMD_JJ(d, e, a, b, c, x[ 9], 11);
    RMD_JJ(c, d, e, a, b, x[ 7],  6); RMD_JJ(b, c, d, e, a, x[12],  8);
    RMD_JJ(a, b, c, d, e, x[ 2], 13); RMD_JJ(e, a, b, c, d, x[10], 12);
    RMD_JJ(d, e, a, b, c, x[14],  5); RMD_JJ(c, d, e, a, b, x[ 1], 12);
    RMD_JJ(b, c, d, e, a, x[ 3], 13); RMD_JJ(a, b, c, d, e, x[ 8], 14);
    RMD_JJ(e, a, b, c, d, x[11], 11); RMD_JJ(d, e, a, b, c, x[ 6],  8);
    RMD_JJ(c, d, e, a, b, x[15],  5); RMD_JJ(b, c, d, e, a, x[13],  6);

    /* Round 1 - right */
    RMD_JJJ(aa, bb, cc, dd, ee, x[ 5],  8); RMD_JJJ(ee, aa, bb, cc, dd, x[14],  9);
    RMD_JJJ(dd, ee, aa, bb, cc, x[ 7],  9); RMD_JJJ(cc, dd, ee, aa, bb, x[ 0], 11);
    RMD_JJJ(bb, cc, dd, ee, aa, x[ 9], 13); RMD_JJJ(aa, bb, cc, dd, ee, x[ 2], 15);
    RMD_JJJ(ee, aa, bb, cc, dd, x[11], 15); RMD_JJJ(dd, ee, aa, bb, cc, x[ 4],  5);
    RMD_JJJ(cc, dd, ee, aa, bb, x[13],  7); RMD_JJJ(bb, cc, dd, ee, aa, x[ 6],  7);
    RMD_JJJ(aa, bb, cc, dd, ee, x[15],  8); RMD_JJJ(ee, aa, bb, cc, dd, x[ 8], 11);
    RMD_JJJ(dd, ee, aa, bb, cc, x[ 1], 14); RMD_JJJ(cc, dd, ee, aa, bb, x[10], 14);
    RMD_JJJ(bb, cc, dd, ee, aa, x[ 3], 12); RMD_JJJ(aa, bb, cc, dd, ee, x[12],  6);

    /* Round 2 - right */
    RMD_III(ee, aa, bb, cc, dd, x[ 6],  9); RMD_III(dd, ee, aa, bb, cc, x[11], 13);
    RMD_III(cc, dd, ee, aa, bb, x[ 3], 15); RMD_III(bb, cc, dd, ee, aa, x[ 7],  7);
    RMD_III(aa, bb, cc, dd, ee, x[ 0], 12); RMD_III(ee, aa, bb, cc, dd, x[13],  8);
    RMD_III(dd, ee, aa, bb, cc, x[ 5],  9); RMD_III(cc, dd, ee, aa, bb, x[10], 11);
    RMD_III(bb, cc, dd, ee, aa, x[14],  7); RMD_III(aa, bb, cc, dd, ee, x[15],  7);
    RMD_III(ee, aa, bb, cc, dd, x[ 8], 12); RMD_III(dd, ee, aa, bb, cc, x[12],  7);
    RMD_III(cc, dd, ee, aa, bb, x[ 4],  6); RMD_III(bb, cc, dd, ee, aa, x[ 9], 15);
    RMD_III(aa, bb, cc, dd, ee, x[ 1], 13); RMD_III(ee, aa, bb, cc, dd, x[ 2], 11);

    /* Round 3 - right */
    RMD_HHH(dd, ee, aa, bb, cc, x[15],  9); RMD_HHH(cc, dd, ee, aa, bb, x[ 5],  7);
    RMD_HHH(bb, cc, dd, ee, aa, x[ 1], 15); RMD_HHH(aa, bb, cc, dd, ee, x[ 3], 11);
    RMD_HHH(ee, aa, bb, cc, dd, x[ 7],  8); RMD_HHH(dd, ee, aa, bb, cc, x[14],  6);
    RMD_HHH(cc, dd, ee, aa, bb, x[ 6],  6); RMD_HHH(bb, cc, dd, ee, aa, x[ 9], 14);
    RMD_HHH(aa, bb, cc, dd, ee, x[11], 12); RMD_HHH(ee, aa, bb, cc, dd, x[ 8], 13);
    RMD_HHH(dd, ee, aa, bb, cc, x[12],  5); RMD_HHH(cc, dd, ee, aa, bb, x[ 2], 14);
    RMD_HHH(bb, cc, dd, ee, aa, x[10], 13); RMD_HHH(aa, bb, cc, dd, ee, x[ 0], 13);
    RMD_HHH(ee, aa, bb, cc, dd, x[ 4],  7); RMD_HHH(dd, ee, aa, bb, cc, x[13],  5);

    /* Round 4 - right */
    RMD_GGG(cc, dd, ee, aa, bb, x[ 8], 15); RMD_GGG(bb, cc, dd, ee, aa, x[ 6],  5);
    RMD_GGG(aa, bb, cc, dd, ee, x[ 4],  8); RMD_GGG(ee, aa, bb, cc, dd, x[ 1], 11);
    RMD_GGG(dd, ee, aa, bb, cc, x[ 3], 14); RMD_GGG(cc, dd, ee, aa, bb, x[11], 14);
    RMD_GGG(bb, cc, dd, ee, aa, x[15],  6); RMD_GGG(aa, bb, cc, dd, ee, x[ 0], 14);
    RMD_GGG(ee, aa, bb, cc, dd, x[ 5],  6); RMD_GGG(dd, ee, aa, bb, cc, x[12],  9);
    RMD_GGG(cc, dd, ee, aa, bb, x[ 2], 12); RMD_GGG(bb, cc, dd, ee, aa, x[13],  9);
    RMD_GGG(aa, bb, cc, dd, ee, x[ 9], 12); RMD_GGG(ee, aa, bb, cc, dd, x[ 7],  5);
    RMD_GGG(dd, ee, aa, bb, cc, x[10], 15); RMD_GGG(cc, dd, ee, aa, bb, x[14],  8);

    /* Round 5 - right */
    RMD_FFF(bb, cc, dd, ee, aa, x[12],  8); RMD_FFF(aa, bb, cc, dd, ee, x[15],  5);
    RMD_FFF(ee, aa, bb, cc, dd, x[10], 12); RMD_FFF(dd, ee, aa, bb, cc, x[ 4],  9);
    RMD_FFF(cc, dd, ee, aa, bb, x[ 1], 12); RMD_FFF(bb, cc, dd, ee, aa, x[ 5],  5);
    RMD_FFF(aa, bb, cc, dd, ee, x[ 8], 14); RMD_FFF(ee, aa, bb, cc, dd, x[ 7],  6);
    RMD_FFF(dd, ee, aa, bb, cc, x[ 6],  8); RMD_FFF(cc, dd, ee, aa, bb, x[ 2], 13);
    RMD_FFF(bb, cc, dd, ee, aa, x[13],  6); RMD_FFF(aa, bb, cc, dd, ee, x[14],  5);
    RMD_FFF(ee, aa, bb, cc, dd, x[ 0], 15); RMD_FFF(dd, ee, aa, bb, cc, x[ 3], 13);
    RMD_FFF(cc, dd, ee, aa, bb, x[ 9], 11); RMD_FFF(bb, cc, dd, ee, aa, x[11], 11);

    /* Finalize */
    t = state[1] + c + dd;
    state[1] = state[2] + d + ee;
    state[2] = state[3] + e + aa;
    state[3] = state[4] + a + bb;
    state[4] = state[0] + b + cc;
    state[0] = t;
}

static void ripemd160(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t state[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    uint8_t buffer[64];
    size_t total_len = len;
    size_t remaining = len;

    /* Process full blocks */
    while (remaining >= 64) {
        ripemd160_transform(state, data);
        data += 64;
        remaining -= 64;
    }

    /* Buffer remaining bytes */
    memcpy(buffer, data, remaining);

    /* Padding */
    buffer[remaining++] = 0x80;
    if (remaining > 56) {
        memset(buffer + remaining, 0, 64 - remaining);
        ripemd160_transform(state, buffer);
        remaining = 0;
    }
    memset(buffer + remaining, 0, 56 - remaining);

    /* Length in bits (little-endian) */
    uint64_t bits = total_len * 8;
    buffer[56] = (uint8_t)(bits);
    buffer[57] = (uint8_t)(bits >> 8);
    buffer[58] = (uint8_t)(bits >> 16);
    buffer[59] = (uint8_t)(bits >> 24);
    buffer[60] = (uint8_t)(bits >> 32);
    buffer[61] = (uint8_t)(bits >> 40);
    buffer[62] = (uint8_t)(bits >> 48);
    buffer[63] = (uint8_t)(bits >> 56);

    ripemd160_transform(state, buffer);

    /* Output (little-endian) */
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(state[i]);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(state[i] >> 24);
    }
}

/* BIP-322 signature generation */

op_error_t bip322_signature_generate_p2wpkh(
    const uint8_t privkey[32],
    const uint8_t hash[SHA256_HASH_LENGTH],
    bip322_signature_t *sig) {

    if (!privkey || !hash || !sig) return OP_ERROR_INVALID_INPUT;

    secp256k1_context *ctx = get_secp_context();
    if (!ctx) return OP_ERROR_CRYPTO_FAILED;

    /* Create ECDSA signature */
    secp256k1_ecdsa_signature ecdsa_sig;
    if (!secp256k1_ecdsa_sign(ctx, &ecdsa_sig, hash, privkey, NULL, NULL)) {
        return OP_ERROR_SIGNATURE_FAILED;
    }

    /* Serialize signature in DER format */
    uint8_t der_sig[72];
    size_t der_len = 72;
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_sig, &der_len, &ecdsa_sig)) {
        return OP_ERROR_SIGNATURE_FAILED;
    }

    /* Get public key */
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey)) {
        return OP_ERROR_CRYPTO_FAILED;
    }

    uint8_t pubkey_bytes[33];
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

    /* Build witness: [signature + sighash_type, pubkey] */
    sig->script_sig_length = 0;
    sig->witness.num_items = 2;

    /* First item: DER signature + SIGHASH_ALL (0x01) */
    sig->witness.items[0].length = der_len + 1;
    memcpy(sig->witness.items[0].data, der_sig, der_len);
    sig->witness.items[0].data[der_len] = 0x01; /* SIGHASH_ALL */

    /* Second item: compressed public key */
    sig->witness.items[1].length = 33;
    memcpy(sig->witness.items[1].data, pubkey_bytes, 33);

    return OP_SUCCESS;
}

op_error_t bip322_signature_generate_p2tr(
    const uint8_t privkey[32],
    const uint8_t hash[SHA256_HASH_LENGTH],
    bip322_signature_t *sig) {

    if (!privkey || !hash || !sig) return OP_ERROR_INVALID_INPUT;

    secp256k1_context *ctx = get_secp_context();
    if (!ctx) return OP_ERROR_CRYPTO_FAILED;

    /* Create keypair */
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, privkey)) {
        return OP_ERROR_CRYPTO_FAILED;
    }

    /* Get x-only pubkey for tweak calculation */
    secp256k1_xonly_pubkey xonly_pubkey;
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair)) {
        return OP_ERROR_CRYPTO_FAILED;
    }

    uint8_t xonly_bytes[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, xonly_bytes, &xonly_pubkey)) {
        return OP_ERROR_CRYPTO_FAILED;
    }

    /* Compute BIP86 tweak = tagged_hash("TapTweak", xonly_pubkey) */
    uint8_t tag_hash[32];
    sha256((const uint8_t*)"TapTweak", 8, tag_hash);

    sha256_t hash_ctx;
    sha256_init(&hash_ctx);
    sha256_update(&hash_ctx, tag_hash, 32);
    sha256_update(&hash_ctx, tag_hash, 32);
    sha256_update(&hash_ctx, xonly_bytes, 32);
    uint8_t tweak[32];
    sha256_final(&hash_ctx, tweak);

    /* Apply tweak to keypair */
    if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak)) {
        return OP_ERROR_CRYPTO_FAILED;
    }

    /* Create Schnorr signature */
    uint8_t schnorr_sig[64];
    if (!secp256k1_schnorrsig_sign32(ctx, schnorr_sig, hash, &keypair, NULL)) {
        return OP_ERROR_SIGNATURE_FAILED;
    }

    /* Build witness: [signature] (no sighash byte for default sighash) */
    sig->script_sig_length = 0;
    sig->witness.num_items = 1;
    sig->witness.items[0].length = 64;
    memcpy(sig->witness.items[0].data, schnorr_sig, 64);

    return OP_SUCCESS;
}

/* BIP-322 signature verification */

op_error_t bip322_signature_verify(
    const bip322_signature_t *sig,
    const uint8_t hash[SHA256_HASH_LENGTH],
    const script_pubkey_t *script_pubkey) {

    if (!sig || !hash || !script_pubkey) return OP_ERROR_INVALID_INPUT;

    /* ScriptSig must be empty for witness-based scripts */
    if (sig->script_sig_length != 0) {
        return OP_ERROR_VERIFICATION_FAILED;
    }

    script_type_t script_type = script_pubkey_get_type(script_pubkey);

    secp256k1_context *ctx = get_secp_context();
    if (!ctx) return OP_ERROR_CRYPTO_FAILED;

    if (script_type == SCRIPT_TYPE_P2WPKH) {
        /* P2WPKH witness: [signature, pubkey] */
        if (sig->witness.num_items != 2) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        /* Parse signature (DER + sighash byte) */
        if (sig->witness.items[0].length < 2) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        size_t der_len = sig->witness.items[0].length - 1;
        secp256k1_ecdsa_signature ecdsa_sig;
        if (!secp256k1_ecdsa_signature_parse_der(ctx, &ecdsa_sig,
                sig->witness.items[0].data, der_len)) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        /* Parse public key */
        if (sig->witness.items[1].length != 33) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey,
                sig->witness.items[1].data, sig->witness.items[1].length)) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        /* Verify pubkey matches script */
        uint8_t pubkey_bytes[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

        uint8_t sha_hash[32];
        sha256(pubkey_bytes, 33, sha_hash);

        uint8_t hash160[20];
        ripemd160(sha_hash, 32, hash160);

        /* Script is: OP_0 0x14 <20-byte-hash> */
        if (memcmp(hash160, script_pubkey->data + 2, 20) != 0) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        /* Verify signature */
        if (!secp256k1_ecdsa_verify(ctx, &ecdsa_sig, hash, &pubkey)) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

    } else if (script_type == SCRIPT_TYPE_P2TR) {
        /* P2TR witness: [signature] (64 bytes for default sighash, 65 for explicit) */
        if (sig->witness.num_items != 1) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        if (sig->witness.items[0].length != 64 && sig->witness.items[0].length != 65) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        /* Extract x-only pubkey from script */
        /* Script is: OP_1 0x20 <32-byte-x-only-pubkey> */
        secp256k1_xonly_pubkey xonly_pubkey;
        if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, script_pubkey->data + 2)) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

        /* Verify Schnorr signature */
        if (!secp256k1_schnorrsig_verify(ctx, sig->witness.items[0].data, hash, 32, &xonly_pubkey)) {
            return OP_ERROR_VERIFICATION_FAILED;
        }

    } else {
        return OP_ERROR_UNSUPPORTED_SCRIPT_TYPE;
    }

    return OP_SUCCESS;
}

/* Ownership proof serialization */

op_error_t ownership_proof_serialize(
    const ownership_proof_t *proof,
    uint8_t *out,
    size_t *out_len) {

    if (!proof || !out || !out_len) return OP_ERROR_INVALID_INPUT;

    size_t offset = 0;

    /* Serialize proof body */
    size_t body_len = *out_len;
    op_error_t err = proof_body_serialize(&proof->body, out, &body_len);
    if (err != OP_SUCCESS) return err;
    offset += body_len;

    /* Serialize signature */
    size_t sig_len = *out_len - offset;
    err = bip322_signature_serialize(&proof->signature, out + offset, &sig_len);
    if (err != OP_SUCCESS) return err;
    offset += sig_len;

    *out_len = offset;
    return OP_SUCCESS;
}

op_error_t ownership_proof_deserialize(
    const uint8_t *data,
    size_t data_len,
    ownership_proof_t *proof) {

    if (!data || !proof) return OP_ERROR_INVALID_INPUT;

    size_t offset = 0;

    /* Deserialize proof body */
    size_t body_consumed;
    op_error_t err = proof_body_deserialize(data, data_len, &proof->body, &body_consumed);
    if (err != OP_SUCCESS) return err;
    offset += body_consumed;

    /* Deserialize signature */
    size_t sig_consumed;
    err = bip322_signature_deserialize(data + offset, data_len - offset, &proof->signature, &sig_consumed);
    if (err != OP_SUCCESS) return err;

    return OP_SUCCESS;
}

/* Ownership proof generation */

op_error_t ownership_proof_generate(
    const uint8_t privkey[32],
    const script_pubkey_t *script_pubkey,
    const ownership_id_t *identifiers,
    size_t num_identifiers,
    const uint8_t *commitment_data,
    size_t commitment_len,
    bool user_confirmation,
    ownership_proof_t *proof) {

    if (!privkey || !script_pubkey || !proof) return OP_ERROR_INVALID_INPUT;
    if (num_identifiers > 0 && !identifiers) return OP_ERROR_INVALID_INPUT;
    if (commitment_len > 0 && !commitment_data) return OP_ERROR_INVALID_INPUT;

    /* Detect script type */
    script_type_t script_type = script_pubkey_get_type(script_pubkey);
    if (script_type == SCRIPT_TYPE_UNKNOWN) {
        return OP_ERROR_UNSUPPORTED_SCRIPT_TYPE;
    }

    /* Initialize proof body */
    uint8_t flags = user_confirmation ? PROOF_FLAG_USER_CONFIRMATION : PROOF_FLAG_NONE;
    op_error_t err = proof_body_init(&proof->body, flags, identifiers, num_identifiers);
    if (err != OP_SUCCESS) return err;

    /* Compute signature hash */
    uint8_t sig_hash[SHA256_HASH_LENGTH];
    err = proof_body_signature_hash(&proof->body, script_pubkey, commitment_data, commitment_len, sig_hash);
    if (err != OP_SUCCESS) return err;

    /* Generate signature */
    if (script_type == SCRIPT_TYPE_P2WPKH) {
        err = bip322_signature_generate_p2wpkh(privkey, sig_hash, &proof->signature);
    } else if (script_type == SCRIPT_TYPE_P2TR) {
        err = bip322_signature_generate_p2tr(privkey, sig_hash, &proof->signature);
    } else {
        return OP_ERROR_UNSUPPORTED_SCRIPT_TYPE;
    }

    return err;
}

/* Ownership proof verification */

op_error_t ownership_proof_verify(
    const ownership_proof_t *proof,
    const script_pubkey_t *script_pubkey,
    const uint8_t *commitment_data,
    size_t commitment_len,
    bool require_user_confirmation) {

    if (!proof || !script_pubkey) return OP_ERROR_INVALID_INPUT;
    if (commitment_len > 0 && !commitment_data) return OP_ERROR_INVALID_INPUT;

    /* Check user confirmation flag if required */
    if (require_user_confirmation &&
        !(proof->body.flags & PROOF_FLAG_USER_CONFIRMATION)) {
        return OP_ERROR_VERIFICATION_FAILED;
    }

    /* Compute signature hash */
    uint8_t sig_hash[SHA256_HASH_LENGTH];
    op_error_t err = proof_body_signature_hash(&proof->body, script_pubkey, commitment_data, commitment_len, sig_hash);
    if (err != OP_SUCCESS) return err;

    /* Verify signature */
    return bip322_signature_verify(&proof->signature, sig_hash, script_pubkey);
}