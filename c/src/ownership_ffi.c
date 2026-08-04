/* WabiSabi C library — ownership-proof FFI (SLIP-0019 / BIP-322).
 *
 * Thin serialization bridge over the self-contained ownership-proof
 * implementation in ownership_proof.c. See include/ownership_ffi.h for the
 * public contract and include/wabisabi_ffi.h for the shared error enum.
 */
#include <stdint.h>
#include <string.h>
#include "../include/ownership_ffi.h"
#include "ownership_proof.h"

/* Map the self-contained ownership_proof.c status codes onto the FFI error
 * enum. Verification/signature failures collapse to WABISABI_ERR_INVALID_PROOF;
 * malformed input collapses to WABISABI_ERR_PARSE. */
static wabisabi_error_t
map_op_error(op_error_t e) {
    switch (e) {
    case OP_SUCCESS:
        return WABISABI_OK;
    case OP_ERROR_INVALID_INPUT:
        return WABISABI_ERR_NULL_PTR;
    case OP_ERROR_BUFFER_TOO_SMALL:
        return WABISABI_ERR_BUFFER_TOO_SMALL;
    case OP_ERROR_INVALID_FORMAT:
    case OP_ERROR_INVALID_VERSION_MAGIC:
        return WABISABI_ERR_PARSE;
    case OP_ERROR_SIGNATURE_FAILED:
    case OP_ERROR_VERIFICATION_FAILED:
    case OP_ERROR_UNSUPPORTED_SCRIPT_TYPE:
        return WABISABI_ERR_INVALID_PROOF;
    default:
        return WABISABI_ERR_PARSE;
    }
}

/* Populate a script_pubkey_t from a raw scriptPubKey buffer. */
static wabisabi_error_t
load_script_pubkey(const uint8_t* bytes, int len, script_pubkey_t* out) {
    if (!bytes && len != 0) {
        return WABISABI_ERR_NULL_PTR;
    }
    if (len < 0 || (size_t)len > MAX_SCRIPT_LENGTH) {
        return WABISABI_ERR_INVALID_LENGTH;
    }
    out->length = (size_t)len;
    if (len > 0) {
        memcpy(out->data, bytes, (size_t)len);
    }
    return WABISABI_OK;
}

wabisabi_error_t
wabisabi_ownership_proof_generate(
    const uint8_t privkey[32],
    int spk_type,
    const uint8_t* identifiers, int n_identifiers,
    const uint8_t* commitment, int commitment_len,
    int user_confirmation,
    uint8_t* out, int out_cap, int* out_len) {

    if (!privkey || !out || !out_len) {
        return WABISABI_ERR_NULL_PTR;
    }
    if (n_identifiers < 0 || n_identifiers > MAX_OWNERSHIP_IDENTIFIERS ||
        (n_identifiers > 0 && !identifiers)) {
        return WABISABI_ERR_INVALID_LENGTH;
    }
    if (commitment_len < 0 || (commitment_len > 0 && !commitment)) {
        return WABISABI_ERR_INVALID_LENGTH;
    }

    /* Derive the scriptPubKey from the private key and the requested type, the
     * same way NBitcoin's key.PubKey.GetScriptPubKey(scriptPubKeyType) does. */
    script_type_t st;
    switch (spk_type) {
    case WABISABI_SPK_P2WPKH:
        st = SCRIPT_TYPE_P2WPKH;
        break;
    case WABISABI_SPK_P2TR:
        st = SCRIPT_TYPE_P2TR;
        break;
    default:
        return WABISABI_ERR_INVALID_PROOF;
    }

    script_pubkey_t spk;
    op_error_t derr = script_pubkey_from_privkey(privkey, st, &spk);
    if (derr != OP_SUCCESS) {
        return map_op_error(derr);
    }

    /* ownership_id_t is a 32-byte struct with no padding, so the flat
     * n_identifiers * OWNERSHIP_ID_LENGTH buffer is layout-compatible. */
    ownership_proof_t proof;
    op_error_t oerr = ownership_proof_generate(
        privkey, &spk,
        (const ownership_id_t*)identifiers, (size_t)n_identifiers,
        commitment, (size_t)commitment_len,
        user_confirmation != 0,
        &proof);
    if (oerr != OP_SUCCESS) {
        return map_op_error(oerr);
    }

    size_t written = (size_t)(out_cap < 0 ? 0 : out_cap);
    oerr = ownership_proof_serialize(&proof, out, &written);
    if (oerr != OP_SUCCESS) {
        return map_op_error(oerr);
    }
    *out_len = (int)written;
    return WABISABI_OK;
}

wabisabi_error_t
wabisabi_ownership_proof_verify(
    const uint8_t* proof_bytes, int proof_len,
    const uint8_t* script_pubkey, int script_pubkey_len,
    const uint8_t* commitment, int commitment_len,
    int require_user_confirmation) {

    if (!proof_bytes || proof_len < 0) {
        return WABISABI_ERR_NULL_PTR;
    }
    if (commitment_len < 0 || (commitment_len > 0 && !commitment)) {
        return WABISABI_ERR_INVALID_LENGTH;
    }

    script_pubkey_t spk;
    wabisabi_error_t serr = load_script_pubkey(script_pubkey, script_pubkey_len, &spk);
    if (serr != WABISABI_OK) {
        return serr;
    }

    ownership_proof_t proof;
    op_error_t oerr = ownership_proof_deserialize(proof_bytes, (size_t)proof_len, &proof);
    if (oerr != OP_SUCCESS) {
        return map_op_error(oerr);
    }

    oerr = ownership_proof_verify(
        &proof, &spk,
        commitment, (size_t)commitment_len,
        require_user_confirmation != 0);
    return map_op_error(oerr);
}
