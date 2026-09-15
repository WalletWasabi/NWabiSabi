/* WabiSabi C library — ownership-proof FFI (SLIP-0019 / BIP-322).
 *
 * These entry points sit alongside the core KVAC FFI (wabisabi_ffi.h) but are a
 * separate concern: they wrap the self-contained ownership-proof implementation
 * (src/ownership_proof.c) so a managed host can create and verify ownership
 * proofs that are byte-for-byte compatible with WalletWasabi's managed
 * OwnershipProof.
 *
 * Both P2WPKH (SegWit v0) and P2TR (Taproot key-path, BIP-86) scriptPubKeys are
 * supported; the script type is detected from the scriptPubKey bytes.
 *
 * A serialized ownership proof is the wire encoding of:
 *   ProofBody       : ["SL\x00\x19"][flags:1][varint(n_ids)][id_0]...[id_{n-1}]
 *   Bip322Signature : [varint(scriptSig_len)][scriptSig][witness stack]
 * exactly as produced/consumed by WalletWasabi's managed serializer.
 */
#pragma once
#include <stdint.h>
#include "wabisabi_ffi.h" /* wabisabi_error_t */

#ifdef __cplusplus
extern "C" {
#endif

/* scriptPubKey type selector for wabisabi_ownership_proof_generate. The native
 * side derives the scriptPubKey from the private key and this type, exactly as
 * NBitcoin's key.PubKey.GetScriptPubKey(scriptPubKeyType) would. */
typedef enum {
    WABISABI_SPK_P2WPKH = 0, /* Segwit v0 (P2WPKH) */
    WABISABI_SPK_P2TR = 1    /* Taproot key-path, BIP-86 (P2TR) */
} wabisabi_spk_type_t;

/**
 * Generate an ownership proof and serialize it to out.
 *
 * The scriptPubKey the proof commits to is derived from privkey and spk_type,
 * so the caller does not pass it explicitly (it matches the scriptPubKey the
 * owner of privkey would spend from).
 *
 * privkey            : 32-byte private key.
 * spk_type           : wabisabi_spk_type_t selecting P2WPKH or P2TR.
 * identifiers        : n_identifiers × 32 ownership-identifier bytes (may be NULL if 0).
 * n_identifiers      : number of ownership identifiers.
 * commitment         : commitment data bound into the signature hash (may be NULL if 0).
 * commitment_len     : byte length of commitment.
 * user_confirmation  : non-zero to set the UserConfirmation flag in the proof body.
 * out                : output buffer for the serialized proof.
 * out_cap            : capacity of out in bytes; WABISABI_ERR_BUFFER_TOO_SMALL if too small.
 * out_len            : set to the serialized proof length on success.
 */
wabisabi_error_t wabisabi_ownership_proof_generate(
    const uint8_t privkey[32],
    int spk_type,
    const uint8_t* identifiers, int n_identifiers,
    const uint8_t* commitment, int commitment_len,
    int user_confirmation,
    uint8_t* out, int out_cap, int* out_len);

/**
 * Verify a serialized ownership proof against a scriptPubKey and commitment.
 *
 * proof_bytes                : serialized ownership proof.
 * proof_len                  : byte length of proof_bytes.
 * script_pubkey / _len       : scriptPubKey the proof must be valid for.
 * commitment / _len          : commitment data bound into the signature hash.
 * require_user_confirmation  : non-zero to reject proofs lacking the UserConfirmation flag.
 *
 * Returns WABISABI_OK if the proof is valid, WABISABI_ERR_INVALID_PROOF if the
 * signature/flags do not verify, or a parse/length error for malformed input.
 */
wabisabi_error_t wabisabi_ownership_proof_verify(
    const uint8_t* proof_bytes, int proof_len,
    const uint8_t* script_pubkey, int script_pubkey_len,
    const uint8_t* commitment, int commitment_len,
    int require_user_confirmation);

#ifdef __cplusplus
}
#endif
