/*
 * ownership_proof.h - SLIP-0019 Ownership Proof Implementation
 *
 * A C implementation compatible with WalletWasabi's managed OwnershipProof.
 * Supports P2WPKH (SegWit) and P2TR (Taproot) script types.
 *
 * Reference: https://github.com/satoshilabs/slips/blob/master/slip-0019.md
 */

#ifndef OWNERSHIP_PROOF_H
#define OWNERSHIP_PROOF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants */
#define OWNERSHIP_ID_LENGTH         32
#define VERSION_MAGIC_LENGTH        4
#define SHA256_HASH_LENGTH          32
#define PUBKEY_COMPRESSED_LENGTH    33
#define PUBKEY_XONLY_LENGTH         32
#define MAX_OWNERSHIP_IDENTIFIERS   256
#define MAX_SCRIPT_LENGTH           520
#define MAX_WITNESS_ITEMS           256
#define MAX_WITNESS_ITEM_LENGTH     520
#define MAX_COMMITMENT_DATA_LENGTH  1024

/* Version magic: "SL\x00\x19" */
static const uint8_t VERSION_MAGIC[VERSION_MAGIC_LENGTH] = { 0x53, 0x4C, 0x00, 0x19 };

/* Error codes */
typedef enum {
    OP_SUCCESS = 0,
    OP_ERROR_INVALID_INPUT = -1,
    OP_ERROR_INVALID_FORMAT = -2,
    OP_ERROR_BUFFER_TOO_SMALL = -3,
    OP_ERROR_INVALID_VERSION_MAGIC = -4,
    OP_ERROR_SIGNATURE_FAILED = -5,
    OP_ERROR_VERIFICATION_FAILED = -6,
    OP_ERROR_UNSUPPORTED_SCRIPT_TYPE = -7,
    OP_ERROR_CRYPTO_FAILED = -8,
    OP_ERROR_MEMORY = -9
} op_error_t;

/* Script types */
typedef enum {
    SCRIPT_TYPE_UNKNOWN = 0,
    SCRIPT_TYPE_P2WPKH = 1,    /* Pay-to-Witness-PubKey-Hash (SegWit v0) */
    SCRIPT_TYPE_P2TR = 2       /* Pay-to-Taproot (SegWit v1) */
} script_type_t;

/* Proof body flags */
typedef enum {
    PROOF_FLAG_NONE = 0,
    PROOF_FLAG_USER_CONFIRMATION = 1
} proof_flags_t;

/* Ownership identifier (32 bytes) */
typedef struct {
    uint8_t bytes[OWNERSHIP_ID_LENGTH];
} ownership_id_t;

/* Proof body structure */
typedef struct {
    uint8_t flags;
    size_t num_identifiers;
    ownership_id_t identifiers[MAX_OWNERSHIP_IDENTIFIERS];
} proof_body_t;

/* Witness stack item */
typedef struct {
    size_t length;
    uint8_t data[MAX_WITNESS_ITEM_LENGTH];
} witness_item_t;

/* Witness stack */
typedef struct {
    size_t num_items;
    witness_item_t items[MAX_WITNESS_ITEMS];
} witness_t;

/* BIP-322 signature */
typedef struct {
    size_t script_sig_length;
    uint8_t script_sig[MAX_SCRIPT_LENGTH];
    witness_t witness;
} bip322_signature_t;

/* Ownership proof */
typedef struct {
    proof_body_t body;
    bip322_signature_t signature;
} ownership_proof_t;

/* Script pubkey */
typedef struct {
    size_t length;
    uint8_t data[MAX_SCRIPT_LENGTH];
} script_pubkey_t;

/*
 * Compute ownership identifier from identification key and scriptPubKey.
 * Uses HMAC-SHA256(identification_key, script_pubkey).
 *
 * @param identification_key  32-byte identification key
 * @param script_pubkey       Script public key
 * @param out                 Output ownership identifier
 * @return OP_SUCCESS or error code
 */
op_error_t ownership_id_compute(
    const uint8_t identification_key[32],
    const script_pubkey_t *script_pubkey,
    ownership_id_t *out);

/*
 * Initialize proof body with flags and identifiers.
 *
 * @param body                Output proof body
 * @param flags               Proof flags
 * @param identifiers         Array of ownership identifiers
 * @param num_identifiers     Number of identifiers
 * @return OP_SUCCESS or error code
 */
op_error_t proof_body_init(
    proof_body_t *body,
    uint8_t flags,
    const ownership_id_t *identifiers,
    size_t num_identifiers);

/*
 * Serialize proof body to bytes.
 *
 * @param body     Proof body to serialize
 * @param out      Output buffer
 * @param out_len  Output buffer size (in), actual size (out)
 * @return OP_SUCCESS or error code
 */
op_error_t proof_body_serialize(
    const proof_body_t *body,
    uint8_t *out,
    size_t *out_len);

/*
 * Deserialize proof body from bytes.
 *
 * @param data      Input data
 * @param data_len  Input data length
 * @param body      Output proof body
 * @param consumed  Number of bytes consumed
 * @return OP_SUCCESS or error code
 */
op_error_t proof_body_deserialize(
    const uint8_t *data,
    size_t data_len,
    proof_body_t *body,
    size_t *consumed);

/*
 * Compute signature hash for proof verification/generation.
 * hash = SHA256(proof_body || proof_footer)
 * where proof_footer = varint(script_len) || script || varint(commitment_len) || commitment
 *
 * @param body             Proof body
 * @param script_pubkey    Script public key
 * @param commitment_data  Commitment data
 * @param commitment_len   Commitment data length
 * @param hash_out         Output 32-byte hash
 * @return OP_SUCCESS or error code
 */
op_error_t proof_body_signature_hash(
    const proof_body_t *body,
    const script_pubkey_t *script_pubkey,
    const uint8_t *commitment_data,
    size_t commitment_len,
    uint8_t hash_out[SHA256_HASH_LENGTH]);

/*
 * Serialize BIP-322 signature to bytes.
 *
 * @param sig      Signature to serialize
 * @param out      Output buffer
 * @param out_len  Output buffer size (in), actual size (out)
 * @return OP_SUCCESS or error code
 */
op_error_t bip322_signature_serialize(
    const bip322_signature_t *sig,
    uint8_t *out,
    size_t *out_len);

/*
 * Deserialize BIP-322 signature from bytes.
 *
 * @param data      Input data
 * @param data_len  Input data length
 * @param sig       Output signature
 * @param consumed  Number of bytes consumed
 * @return OP_SUCCESS or error code
 */
op_error_t bip322_signature_deserialize(
    const uint8_t *data,
    size_t data_len,
    bip322_signature_t *sig,
    size_t *consumed);

/*
 * Generate BIP-322 signature for P2WPKH.
 *
 * @param privkey          32-byte private key
 * @param hash             32-byte message hash to sign
 * @param sig              Output signature
 * @return OP_SUCCESS or error code
 */
op_error_t bip322_signature_generate_p2wpkh(
    const uint8_t privkey[32],
    const uint8_t hash[SHA256_HASH_LENGTH],
    bip322_signature_t *sig);

/*
 * Generate BIP-322 signature for P2TR (Taproot key-path spend).
 *
 * @param privkey          32-byte private key
 * @param hash             32-byte message hash to sign
 * @param sig              Output signature
 * @return OP_SUCCESS or error code
 */
op_error_t bip322_signature_generate_p2tr(
    const uint8_t privkey[32],
    const uint8_t hash[SHA256_HASH_LENGTH],
    bip322_signature_t *sig);

/*
 * Verify BIP-322 signature against hash and script pubkey.
 *
 * @param sig             Signature to verify
 * @param hash            32-byte message hash
 * @param script_pubkey   Script public key
 * @return OP_SUCCESS if valid, OP_ERROR_VERIFICATION_FAILED if invalid
 */
op_error_t bip322_signature_verify(
    const bip322_signature_t *sig,
    const uint8_t hash[SHA256_HASH_LENGTH],
    const script_pubkey_t *script_pubkey);

/*
 * Serialize ownership proof to bytes.
 *
 * @param proof    Proof to serialize
 * @param out      Output buffer
 * @param out_len  Output buffer size (in), actual size (out)
 * @return OP_SUCCESS or error code
 */
op_error_t ownership_proof_serialize(
    const ownership_proof_t *proof,
    uint8_t *out,
    size_t *out_len);

/*
 * Deserialize ownership proof from bytes.
 *
 * @param data      Input data
 * @param data_len  Input data length
 * @param proof     Output proof
 * @return OP_SUCCESS or error code
 */
op_error_t ownership_proof_deserialize(
    const uint8_t *data,
    size_t data_len,
    ownership_proof_t *proof);

/*
 * Generate ownership proof.
 *
 * @param privkey              32-byte private key
 * @param script_pubkey        Script public key (caller must provide)
 * @param identifiers          Array of ownership identifiers
 * @param num_identifiers      Number of identifiers
 * @param commitment_data      Commitment data
 * @param commitment_len       Commitment data length
 * @param user_confirmation    Whether user confirmed ownership
 * @param proof                Output proof
 * @return OP_SUCCESS or error code
 */
op_error_t ownership_proof_generate(
    const uint8_t privkey[32],
    const script_pubkey_t *script_pubkey,
    const ownership_id_t *identifiers,
    size_t num_identifiers,
    const uint8_t *commitment_data,
    size_t commitment_len,
    bool user_confirmation,
    ownership_proof_t *proof);

/*
 * Verify ownership proof.
 *
 * @param proof                    Proof to verify
 * @param script_pubkey            Script public key
 * @param commitment_data          Commitment data
 * @param commitment_len           Commitment data length
 * @param require_user_confirmation  Whether to require user confirmation flag
 * @return OP_SUCCESS if valid, error code otherwise
 */
op_error_t ownership_proof_verify(
    const ownership_proof_t *proof,
    const script_pubkey_t *script_pubkey,
    const uint8_t *commitment_data,
    size_t commitment_len,
    bool require_user_confirmation);

/*
 * Detect script type from scriptPubKey.
 *
 * @param script_pubkey   Script public key
 * @return Script type or SCRIPT_TYPE_UNKNOWN
 */
script_type_t script_pubkey_get_type(const script_pubkey_t *script_pubkey);

/*
 * Derive scriptPubKey from private key.
 *
 * @param privkey        32-byte private key
 * @param script_type    Type of script to generate
 * @param script_pubkey  Output script public key
 * @return OP_SUCCESS or error code
 */
op_error_t script_pubkey_from_privkey(
    const uint8_t privkey[32],
    script_type_t script_type,
    script_pubkey_t *script_pubkey);

/* Utility functions */

/*
 * Write a Bitcoin-style varint.
 *
 * @param value    Value to encode
 * @param out      Output buffer
 * @param out_len  Output buffer size (in), bytes written (out)
 * @return OP_SUCCESS or error code
 */
op_error_t varint_write(uint64_t value, uint8_t *out, size_t *out_len);

/*
 * Read a Bitcoin-style varint.
 *
 * @param data      Input data
 * @param data_len  Input data length
 * @param value     Output value
 * @param consumed  Bytes consumed
 * @return OP_SUCCESS or error code
 */
op_error_t varint_read(const uint8_t *data, size_t data_len, uint64_t *value, size_t *consumed);

/*
 * Convert bytes to hex string.
 *
 * @param data      Input data
 * @param data_len  Input data length
 * @param hex       Output hex string (must be at least data_len*2+1 bytes)
 */
void bytes_to_hex(const uint8_t *data, size_t data_len, char *hex);

/*
 * Convert hex string to bytes.
 *
 * @param hex       Input hex string
 * @param out       Output buffer
 * @param out_len   Output buffer size (in), bytes written (out)
 * @return OP_SUCCESS or error code
 */
op_error_t hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* OWNERSHIP_PROOF_H */