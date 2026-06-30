/* WabiSabi C library — stateless serialization bridge for cross-language interop.
 * See include/wabisabi_ffi.h for wire format documentation.
 *
 * All state is passed explicitly: the caller owns the mutable issuer state
 * (serialized bytes) and the client validation state (WABISABI_VALIDATION_SIZE bytes).
 * There are no heap-allocated handles.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/wabisabi_ffi.h"
#include "client.h"
#include "credential.h"
#include "generators.h"
#include "issuer.h"
#include "mac.h"
#include "proof.h"
#include "wabisabi_types.h"

/* Zeroize a memory region in a way the compiler cannot optimize away. */
static void
secure_zero(void* buf, size_t n) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (n--) {
        *p++ = 0;
    }
}

/* ---- Wire-format helpers ---- */

static void
write_scalar(uint8_t* buf, const wabisabi_scalar_t* s) {
    memcpy(buf, s->data, WABISABI_SCALAR_SIZE);
}

static void
read_scalar(const uint8_t* buf, wabisabi_scalar_t* s) {
    memcpy(s->data, buf, WABISABI_SCALAR_SIZE);
}

/* Returns WABISABI_GE_SIZE (bytes written). */
static int
write_ge(uint8_t* buf, const wabisabi_ge_t* ge) {
    wabisabi_ge_serialize(buf, ge);
    return WABISABI_GE_SIZE;
}

/* Returns WABISABI_GE_SIZE on success, -1 on parse error. */
static int
read_ge(const uint8_t* buf, wabisabi_ge_t* ge) {
    if (!wabisabi_ge_parse(ge, buf)) {
        return -1;
    }
    return WABISABI_GE_SIZE;
}

/*
 * Returns bytes written (2 + n_nonces*GE_SIZE + n_responses*SCALAR_SIZE).
 */
static int
write_proof(uint8_t* buf, const wabisabi_proof_t* p) {
    if (p->n_nonces > 255 || p->n_responses > 255) {
        return -1;
    }
    buf[0] = (uint8_t)p->n_nonces;
    buf[1] = (uint8_t)p->n_responses;
    int off = 2;
    for (int i = 0; i < p->n_nonces; i++, off += WABISABI_GE_SIZE) {
        write_ge(buf + off, &p->public_nonces[i]);
    }
    for (int i = 0; i < p->n_responses; i++, off += WABISABI_SCALAR_SIZE) {
        write_scalar(buf + off, &p->responses[i]);
    }
    return off;
}

/* Serialized size of a proof, in bytes (mirrors write_proof). */
static int
proof_serialized_size(const wabisabi_proof_t* p) {
    return 2 + p->n_nonces * WABISABI_GE_SIZE + p->n_responses * WABISABI_SCALAR_SIZE;
}

/* Returns bytes consumed, or -1 on error. */
static int
read_proof(const uint8_t* buf, int buf_remaining, wabisabi_proof_t* p) {
    if (buf_remaining < 2) {
        return -1;
    }
    int n_nonces = buf[0];
    int n_responses = buf[1];

    if (n_nonces > PROOF_MAX_EQUATIONS) {
        return -1;
    }
    if (n_responses > PROOF_MAX_WITNESSES) {
        return -1;
    }

    int needed = 2 + n_nonces * WABISABI_GE_SIZE + n_responses * WABISABI_SCALAR_SIZE;
    if (buf_remaining < needed) {
        return -1;
    }

    p->n_nonces = n_nonces;
    p->n_responses = n_responses;
    int off = 2;
    for (int i = 0; i < n_nonces; i++, off += WABISABI_GE_SIZE) {
        if (read_ge(buf + off, &p->public_nonces[i]) < 0) {
            return -1;
        }
    }
    for (int i = 0; i < n_responses; i++, off += WABISABI_SCALAR_SIZE) {
        read_scalar(buf + off, &p->responses[i]);
    }
    return off;
}

/* Returns WABISABI_MAC_SIZE (bytes written). */
static int
write_mac(uint8_t* buf, const wabisabi_mac_t* mac) {
    write_scalar(buf, &mac->t);
    write_ge(buf + WABISABI_SCALAR_SIZE, &mac->v);
    return WABISABI_MAC_SIZE;
}

/* Returns WABISABI_MAC_SIZE on success, -1 on error. */
static int
read_mac(const uint8_t* buf, int buf_remaining, wabisabi_mac_t* mac) {
    if (buf_remaining < WABISABI_MAC_SIZE) {
        return -1;
    }
    read_scalar(buf, &mac->t);
    if (read_ge(buf + WABISABI_SCALAR_SIZE, &mac->v) < 0) {
        return -1;
    }
    return WABISABI_MAC_SIZE;
}

/* Returns GE_SIZE*(1+n_bits) bytes written. */
static int
write_issuance_request(uint8_t* buf, const wabisabi_issuance_request_t* req) {
    int off = write_ge(buf, &req->ma);
    for (int i = 0; i < req->n_bit_commitments; i++, off += WABISABI_GE_SIZE) {
        write_ge(buf + off, &req->bit_commitments[i]);
    }
    return off;
}

/* Serialized size of an issuance request, in bytes (mirrors write_issuance_request). */
static int
issuance_request_serialized_size(const wabisabi_issuance_request_t* req) {
    return WABISABI_GE_SIZE * (1 + req->n_bit_commitments);
}

/* n_bits must be caller-validated against WABISABI_MAX_RANGE_WIDTH before calling. */
static int
read_issuance_request(const uint8_t* buf, int buf_remaining, wabisabi_issuance_request_t* req, int n_bits) {
    int needed = WABISABI_GE_SIZE * (1 + n_bits);
    if (buf_remaining < needed) {
        return -1;
    }
    if (read_ge(buf, &req->ma) < 0) {
        return -1;
    }
    int off = WABISABI_GE_SIZE;
    req->n_bit_commitments = n_bits;
    for (int i = 0; i < n_bits; i++, off += WABISABI_GE_SIZE) {
        if (read_ge(buf + off, &req->bit_commitments[i]) < 0) {
            return -1;
        }
    }
    return off;
}

/* Returns WABISABI_PRESENTATION_SIZE bytes written. */
static int
write_presentation(uint8_t* buf, const wabisabi_presentation_t* p) {
    int off = 0;
    off += write_ge(buf + off, &p->ca);
    off += write_ge(buf + off, &p->cx0);
    off += write_ge(buf + off, &p->cx1);
    off += write_ge(buf + off, &p->cv);
    off += write_ge(buf + off, &p->s);
    return off;
}

/* Returns WABISABI_PRESENTATION_SIZE on success, -1 on error. */
static int
read_presentation(const uint8_t* buf, int buf_remaining, wabisabi_presentation_t* p) {
    if (buf_remaining < WABISABI_PRESENTATION_SIZE) {
        return -1;
    }
    int off = 0;
    if (read_ge(buf + off, &p->ca)  < 0) { return -1; } off += WABISABI_GE_SIZE;
    if (read_ge(buf + off, &p->cx0) < 0) { return -1; } off += WABISABI_GE_SIZE;
    if (read_ge(buf + off, &p->cx1) < 0) { return -1; } off += WABISABI_GE_SIZE;
    if (read_ge(buf + off, &p->cv)  < 0) { return -1; } off += WABISABI_GE_SIZE;
    if (read_ge(buf + off, &p->s)   < 0) { return -1; } off += WABISABI_GE_SIZE;
    return off;
}

/* Returns WABISABI_CREDENTIAL_SIZE bytes written. */
static int
write_credential(uint8_t* buf, const wabisabi_credential_t* c) {
    int64_t v = c->value;
    for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
        buf[i] = (uint8_t)(v >> (8 * i));
    }
    int off = WABISABI_VALUE_SIZE;
    write_scalar(buf + off, &c->randomness);
    off += WABISABI_SCALAR_SIZE;
    off += write_mac(buf + off, &c->mac);
    return off;
}

/* Returns WABISABI_CREDENTIAL_SIZE on success, -1 on error. */
static int
read_credential(const uint8_t* buf, int buf_remaining, wabisabi_credential_t* c) {
    if (buf_remaining < WABISABI_CREDENTIAL_SIZE) {
        return -1;
    }
    int64_t v = 0;
    for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
        v |= ((int64_t)buf[i]) << (8 * i);
    }
    c->value = v;
    int off = WABISABI_VALUE_SIZE;
    read_scalar(buf + off, &c->randomness);
    off += WABISABI_SCALAR_SIZE;
    if (read_mac(buf + off, WABISABI_CREDENTIAL_SIZE - off, &c->mac) < 0) {
        return -1;
    }
    return WABISABI_CREDENTIAL_SIZE;
}

/* ---- Validation state serialization ----
 *
 * Format (WABISABI_VALIDATION_SIZE = 353 bytes):
 *   [strobe_state:200][strobe_pos:1][strobe_pos_begin:1][strobe_cur_flags:1]
 *   [n_requested:4 LE]
 *   For each of WABISABI_CREDENTIAL_COUNT requested credentials:
 *     [value:8 LE][randomness:32][ma:33]
 */
static void
write_validation_state(uint8_t* buf, const wabisabi_response_validation_t* val) {
    memcpy(buf, val->transcript.strobe.state, 200);
    buf[200] = val->transcript.strobe.pos;
    buf[201] = val->transcript.strobe.pos_begin;
    buf[202] = val->transcript.strobe.cur_flags;
    int off = 203;

    buf[off++] = (uint8_t)(val->n_requested);
    buf[off++] = (uint8_t)(val->n_requested >> 8);
    buf[off++] = (uint8_t)(val->n_requested >> 16);
    buf[off++] = (uint8_t)(val->n_requested >> 24);

    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int64_t v = val->requested[i].value;
        for (int j = 0; j < 8; j++) {
            buf[off++] = (uint8_t)(v >> (8 * j));
        }
        write_scalar(buf + off, &val->requested[i].randomness);
        off += WABISABI_SCALAR_SIZE;
        write_ge(buf + off, &val->requested[i].ma);
        off += WABISABI_GE_SIZE;
    }
    /* off == WABISABI_VALIDATION_SIZE == 353 */
}

/* Returns 0 on success, -1 on parse error. */
static int
read_validation_state(const uint8_t* buf, wabisabi_response_validation_t* val) {
    memcpy(val->transcript.strobe.state, buf, 200);
    val->transcript.strobe.pos       = buf[200];
    val->transcript.strobe.pos_begin = buf[201];
    val->transcript.strobe.cur_flags = buf[202];
    int off = 203;

    val->n_requested = (int)((uint32_t)buf[off]
                           | ((uint32_t)buf[off+1] << 8)
                           | ((uint32_t)buf[off+2] << 16)
                           | ((uint32_t)buf[off+3] << 24));
    off += 4;

    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int64_t v = 0;
        for (int j = 0; j < 8; j++) {
            v |= ((int64_t)buf[off++]) << (8 * j);
        }
        val->requested[i].value = v;
        read_scalar(buf + off, &val->requested[i].randomness);
        off += WABISABI_SCALAR_SIZE;
        if (read_ge(buf + off, &val->requested[i].ma) < 0) {
            return -1;
        }
        off += WABISABI_GE_SIZE;
    }
    return 0;
}

/* ---- Mutable issuer state serialization ----
 *
 * Format (variable length):
 *   [balance:8 LE][count:4 LE][serial_0:GE_SIZE]...[serial_n-1:GE_SIZE]
 *
 * Returns number of bytes written: 12 + count * WABISABI_GE_SIZE.
 */
/* Serialized size of the mutable issuer state, in bytes (mirrors write_mutable_state). */
static int
mutable_state_serialized_size(const wabisabi_issuer_state_t* issuer) {
    return 12 + issuer->serial_numbers.count * WABISABI_GE_SIZE;
}

static int
write_mutable_state(uint8_t* buf, const wabisabi_issuer_state_t* issuer) {
    int64_t b = issuer->balance;
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)(b >> (8 * i));
    }
    int count = issuer->serial_numbers.count;
    for (int i = 0; i < 4; i++) {
        buf[8 + i] = (uint8_t)(count >> (8 * i));
    }
    int off = 12;
    for (int i = 0; i < WABISABI_MAX_SERIAL_NUMBERS; i++) {
        if (issuer->serial_numbers.used[i]) {
            memcpy(buf + off, issuer->serial_numbers.entries[i], WABISABI_GE_SIZE);
            off += WABISABI_GE_SIZE;
        }
    }
    return off; /* 12 + count * WABISABI_GE_SIZE */
}

/* Returns 0 on success, -1 on error.
 * NULL/empty mstate_in is treated as initial state (balance=0, no serials). */
static int
read_mutable_state(const uint8_t* mstate_in, int mstate_in_len, wabisabi_issuer_state_t* issuer) {
    /* Always start with clean slate */
    issuer->balance = 0;
    memset(&issuer->serial_numbers, 0, sizeof(issuer->serial_numbers));

    if (mstate_in == NULL || mstate_in_len == 0) {
        return 0;
    }
    if (mstate_in_len < 12) {
        return -1;
    }

    int64_t b = 0;
    for (int i = 0; i < 8; i++) {
        b |= ((int64_t)mstate_in[i]) << (8 * i);
    }
    issuer->balance = b;

    int count = (int)((uint32_t)mstate_in[8]
                    | ((uint32_t)mstate_in[9]  << 8)
                    | ((uint32_t)mstate_in[10] << 16)
                    | ((uint32_t)mstate_in[11] << 24));

    if (count < 0 || count > WABISABI_MAX_SERIAL_NUMBERS) {
        return -1;
    }
    if (mstate_in_len < 12 + count * WABISABI_GE_SIZE) {
        return -1;
    }

    for (int i = 0; i < count; i++) {
        wabisabi_ge_t ge;
        const uint8_t* entry = mstate_in + 12 + i * WABISABI_GE_SIZE;
        if (read_ge(entry, &ge) < 0) {
            return -1;
        }
        if (!wabisabi_serial_set_insert(&issuer->serial_numbers, &ge)) {
            return -1; /* hash table full */
        }
    }
    return 0;
}

/* ---- Initialization ---- */

void
wabisabi_init(void) {
    wabisabi_ctx_init();
    wabisabi_generators_init();
}

void
wabisabi_cleanup(void) {
    wabisabi_ctx_cleanup();
}

/* ---- Issuer parameters ---- */

wabisabi_error_t
wabisabi_iparams_from_sk(const uint8_t* sk_bytes, uint8_t* out_bytes) {
    if (!sk_bytes || !out_bytes) {
        return WABISABI_ERR_NULL_PTR;
    }

    wabisabi_sk_t sk;
    read_scalar(sk_bytes,                         &sk.w);
    read_scalar(sk_bytes +     WABISABI_SCALAR_SIZE, &sk.wp);
    read_scalar(sk_bytes + 2 * WABISABI_SCALAR_SIZE, &sk.x0);
    read_scalar(sk_bytes + 3 * WABISABI_SCALAR_SIZE, &sk.x1);
    read_scalar(sk_bytes + 4 * WABISABI_SCALAR_SIZE, &sk.ya);

    wabisabi_iparams_t ip;
    wabisabi_compute_iparams(&ip, &sk);
    secure_zero(&sk, sizeof(sk));

    write_ge(out_bytes,                   &ip.cw);
    write_ge(out_bytes + WABISABI_GE_SIZE, &ip.i);
    return WABISABI_OK;
}

/* ---- Issuer (stateless) ---- */

static wabisabi_error_t
parse_sk(const uint8_t* sk_bytes, wabisabi_sk_t* sk) {
    read_scalar(sk_bytes,                         &sk->w);
    read_scalar(sk_bytes +     WABISABI_SCALAR_SIZE, &sk->wp);
    read_scalar(sk_bytes + 2 * WABISABI_SCALAR_SIZE, &sk->x0);
    read_scalar(sk_bytes + 3 * WABISABI_SCALAR_SIZE, &sk->x1);
    read_scalar(sk_bytes + 4 * WABISABI_SCALAR_SIZE, &sk->ya);
    return WABISABI_OK;
}

/*
 * ZeroRequest wire format:
 *   [Ma_0:GE_SIZE][Ma_1:GE_SIZE]     (2 × issuance_request, 0 bit commitments)
 *   [proof_0][proof_1]               (2 × zero proof: 1 nonce, 1 response)
 */
wabisabi_error_t
wabisabi_issuer_handle_zero(const uint8_t* sk_bytes, int64_t max_amount,
                            const uint8_t* mstate_in, int mstate_in_len,
                            const uint8_t* req_bytes, int req_len,
                            const uint8_t* rand_bytes,
                            uint8_t* resp_out, int resp_out_cap, int* resp_len_out,
                            uint8_t* mstate_out, int mstate_out_cap, int* mstate_out_len) {
    if (!sk_bytes || !req_bytes || !rand_bytes || !resp_out || !resp_len_out
        || !mstate_out || !mstate_out_len) {
        return WABISABI_ERR_NULL_PTR;
    }
    if (req_len < 2 * WABISABI_GE_SIZE) {
        return WABISABI_ERR_INVALID_LENGTH;
    }

    wabisabi_sk_t sk;
    parse_sk(sk_bytes, &sk);

    wabisabi_issuer_state_t issuer;
    wabisabi_issuer_state_init(&issuer, &sk, max_amount);
    secure_zero(&sk, sizeof(sk));

    if (read_mutable_state(mstate_in, mstate_in_len, &issuer) < 0) {
        return WABISABI_ERR_PARSE;
    }

    wabisabi_zero_request_t req;
    int off = 0;
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int n = read_issuance_request(req_bytes + off, req_len - off, &req.requested[i], 0);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int n = read_proof(req_bytes + off, req_len - off, &req.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }

    wabisabi_response_t resp;
    wabisabi_error_t err = wabisabi_issuer_state_handle_zero(&issuer, &req, &resp, rand_bytes);
    if (err != WABISABI_OK) {
        return err;
    }

    int resp_needed = 1 + resp.n_issued * WABISABI_MAC_SIZE;
    for (int i = 0; i < resp.n_issued; i++) {
        resp_needed += proof_serialized_size(&resp.proofs[i]);
    }
    if (resp_out_cap < resp_needed
        || mstate_out_cap < mutable_state_serialized_size(&issuer)) {
        return WABISABI_ERR_BUFFER_TOO_SMALL;
    }

    off = 0;
    resp_out[off++] = (uint8_t)resp.n_issued;
    for (int i = 0; i < resp.n_issued; i++) {
        off += write_mac(resp_out + off, &resp.issued[i]);
    }
    for (int i = 0; i < resp.n_issued; i++) {
        int n = write_proof(resp_out + off, &resp.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }
    *resp_len_out = off;

    *mstate_out_len = write_mutable_state(mstate_out, &issuer);
    return WABISABI_OK;
}

/*
 * RealRequest wire format:
 *   [delta:VALUE_SIZE LE]
 *   [pres_0:PRESENTATION_SIZE][pres_1:PRESENTATION_SIZE]
 *   [req_0: GE_SIZE*(1+width)][req_1: GE_SIZE*(1+width)]
 *   [n_proofs:1][proof_0]...[proof_{n-1}]
 */
wabisabi_error_t
wabisabi_issuer_handle_real(const uint8_t* sk_bytes, int64_t max_amount,
                            const uint8_t* mstate_in, int mstate_in_len,
                            const uint8_t* req_bytes, int req_len,
                            const uint8_t* rand_bytes,
                            uint8_t* resp_out, int resp_out_cap, int* resp_len_out,
                            uint8_t* mstate_out, int mstate_out_cap, int* mstate_out_len) {
    if (!sk_bytes || !req_bytes || !rand_bytes || !resp_out || !resp_len_out
        || !mstate_out || !mstate_out_len) {
        return WABISABI_ERR_NULL_PTR;
    }

    /* delta + presentations + n_requested byte + n_proofs byte (a
     * presentation-only request carries no issuance requests). */
    int min_len = WABISABI_VALUE_SIZE + WABISABI_CREDENTIAL_COUNT * WABISABI_PRESENTATION_SIZE + 1 + 1;
    if (req_len < min_len) {
        return WABISABI_ERR_INVALID_LENGTH;
    }

    wabisabi_sk_t sk;
    parse_sk(sk_bytes, &sk);

    wabisabi_issuer_state_t issuer;
    wabisabi_issuer_state_init(&issuer, &sk, max_amount);
    secure_zero(&sk, sizeof(sk));

    if (read_mutable_state(mstate_in, mstate_in_len, &issuer) < 0) {
        return WABISABI_ERR_PARSE;
    }

    wabisabi_real_request_t req;
    int off = 0;
    int w = issuer.range_proof_width;

    if (w < 0 || w > WABISABI_MAX_RANGE_WIDTH) {
        return WABISABI_ERR_INVALID_BIT_COMMITMENT;
    }

    {
        uint64_t uv = 0;
        for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
            uv |= ((uint64_t)req_bytes[off + i]) << (8 * i);
        }
        req.delta = (int64_t)uv;
        off += WABISABI_VALUE_SIZE;
    }

    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int n = read_presentation(req_bytes + off, req_len - off, &req.presented[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }

    if (off >= req_len) {
        return WABISABI_ERR_INVALID_LENGTH;
    }
    req.n_requested = req_bytes[off++];
    if (req.n_requested != 0 && req.n_requested != WABISABI_CREDENTIAL_COUNT) {
        return WABISABI_ERR_INVALID_CRED_COUNT;
    }

    for (int i = 0; i < req.n_requested; i++) {
        int n = read_issuance_request(req_bytes + off, req_len - off, &req.requested[i], w);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }

    if (off >= req_len) {
        return WABISABI_ERR_INVALID_LENGTH;
    }
    req.n_proofs = req_bytes[off++];
    int max_proofs = WABISABI_CREDENTIAL_COUNT * 2 + 1;
    if (req.n_proofs > max_proofs) {
        return WABISABI_ERR_INVALID_CRED_COUNT;
    }

    for (int i = 0; i < req.n_proofs; i++) {
        int n = read_proof(req_bytes + off, req_len - off, &req.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }

    wabisabi_response_t resp;
    wabisabi_error_t err = wabisabi_issuer_state_handle_real(&issuer, &req, &resp, rand_bytes);
    if (err != WABISABI_OK) {
        return err;
    }

    int resp_needed = 1 + resp.n_issued * WABISABI_MAC_SIZE;
    for (int i = 0; i < resp.n_issued; i++) {
        resp_needed += proof_serialized_size(&resp.proofs[i]);
    }
    if (resp_out_cap < resp_needed
        || mstate_out_cap < mutable_state_serialized_size(&issuer)) {
        return WABISABI_ERR_BUFFER_TOO_SMALL;
    }

    off = 0;
    resp_out[off++] = (uint8_t)resp.n_issued;
    for (int i = 0; i < resp.n_issued; i++) {
        off += write_mac(resp_out + off, &resp.issued[i]);
    }
    for (int i = 0; i < resp.n_issued; i++) {
        int n = write_proof(resp_out + off, &resp.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }
    *resp_len_out = off;

    *mstate_out_len = write_mutable_state(mstate_out, &issuer);
    return WABISABI_OK;
}

/* ---- Client (stateless) ---- */

/*
 * Output wire format: [Ma_0:GE_SIZE][Ma_1:GE_SIZE][proof_0][proof_1]
 * val_out: WABISABI_VALIDATION_SIZE bytes of validation state.
 */
wabisabi_error_t
wabisabi_client_create_zero_request(const uint8_t* rand_bytes,
                                    uint8_t* req_out, int req_out_cap, int* req_len_out,
                                    uint8_t val_out[WABISABI_VALIDATION_SIZE]) {
    if (!rand_bytes || !req_out || !req_len_out || !val_out) {
        return WABISABI_ERR_NULL_PTR;
    }

    /* Zero request does not need iparams or range_proof_width */
    wabisabi_iparams_t dummy_iparams;
    memset(&dummy_iparams, 0, sizeof(dummy_iparams));
    wabisabi_client_state_t client;
    wabisabi_client_state_init(&client, &dummy_iparams, 1 /* dummy max_amount */);

    wabisabi_zero_request_t req;
    wabisabi_response_validation_t val;
    wabisabi_client_state_create_zero_request(&client, rand_bytes, &req, &val);

    int req_needed = WABISABI_CREDENTIAL_COUNT * WABISABI_GE_SIZE;
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        req_needed += proof_serialized_size(&req.proofs[i]);
    }
    if (req_out_cap < req_needed) {
        return WABISABI_ERR_BUFFER_TOO_SMALL;
    }

    int off = 0;
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        off += write_ge(req_out + off, &req.requested[i].ma);
    }
    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        int n = write_proof(req_out + off, &req.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }
    *req_len_out = off;

    write_validation_state(val_out, &val);
    return WABISABI_OK;
}

/*
 * RealRequest wire format (see issuer handler above for layout).
 * val_out: WABISABI_VALIDATION_SIZE bytes of validation state.
 */
wabisabi_error_t
wabisabi_client_create_real_request(const uint8_t* iparams_bytes, int64_t max_amount,
                                    const int64_t* amounts, int n_amounts,
                                    const uint8_t* creds_bytes, int n_creds,
                                    const uint8_t* rand_bytes,
                                    uint8_t* req_out, int req_out_cap, int* req_len_out,
                                    uint8_t val_out[WABISABI_VALIDATION_SIZE]) {
    if (!iparams_bytes || !creds_bytes || !rand_bytes || !req_out || !req_len_out || !val_out) {
        return WABISABI_ERR_NULL_PTR;
    }
    if (n_amounts > 0 && !amounts) {
        return WABISABI_ERR_NULL_PTR;
    }
    if (n_creds < 0 || n_creds > WABISABI_CREDENTIAL_COUNT) {
        return WABISABI_ERR_INVALID_CRED_COUNT;
    }

    wabisabi_iparams_t ip;
    if (read_ge(iparams_bytes, &ip.cw) < 0 ||
        read_ge(iparams_bytes + WABISABI_GE_SIZE, &ip.i) < 0) {
        return WABISABI_ERR_PARSE;
    }

    wabisabi_client_state_t client;
    wabisabi_client_state_init(&client, &ip, max_amount);

    wabisabi_credential_t creds[WABISABI_CREDENTIAL_COUNT];
    for (int i = 0; i < n_creds; i++) {
        int rem = (n_creds - i) * WABISABI_CREDENTIAL_SIZE;
        if (read_credential(creds_bytes + i * WABISABI_CREDENTIAL_SIZE, rem, &creds[i]) < 0) {
            secure_zero(creds, sizeof(creds));
            return WABISABI_ERR_PARSE;
        }
    }

    wabisabi_real_request_t req;
    wabisabi_response_validation_t val;
    wabisabi_client_state_create_real_request(&client, amounts, n_amounts, creds, n_creds,
                                              rand_bytes, &req, &val);
    secure_zero(creds, sizeof(creds));

    int req_needed = WABISABI_VALUE_SIZE
                   + WABISABI_CREDENTIAL_COUNT * WABISABI_PRESENTATION_SIZE
                   + 1  /* n_requested byte */
                   + 1; /* n_proofs byte */
    for (int i = 0; i < req.n_requested; i++) {
        req_needed += issuance_request_serialized_size(&req.requested[i]);
    }
    for (int i = 0; i < req.n_proofs; i++) {
        req_needed += proof_serialized_size(&req.proofs[i]);
    }
    if (req_out_cap < req_needed) {
        return WABISABI_ERR_BUFFER_TOO_SMALL;
    }

    int off = 0;

    int64_t delta = req.delta;
    for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
        req_out[off++] = (uint8_t)(delta >> (8 * i));
    }

    for (int i = 0; i < WABISABI_CREDENTIAL_COUNT; i++) {
        off += write_presentation(req_out + off, &req.presented[i]);
    }

    req_out[off++] = (uint8_t)req.n_requested;
    for (int i = 0; i < req.n_requested; i++) {
        off += write_issuance_request(req_out + off, &req.requested[i]);
    }

    req_out[off++] = (uint8_t)req.n_proofs;
    for (int i = 0; i < req.n_proofs; i++) {
        int n = write_proof(req_out + off, &req.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }
    *req_len_out = off;

    write_validation_state(val_out, &val);
    return WABISABI_OK;
}

/*
 * Response wire format: [mac_0:MAC_SIZE][mac_1:MAC_SIZE][proof_0][proof_1]
 * val_bytes: WABISABI_VALIDATION_SIZE bytes from the corresponding create call.
 * Credential output: CREDENTIAL_COUNT × CREDENTIAL_SIZE bytes.
 */
wabisabi_error_t
wabisabi_client_handle_response(const uint8_t* iparams_bytes,
                                const uint8_t* resp_bytes, int resp_len,
                                const uint8_t val_bytes[WABISABI_VALIDATION_SIZE],
                                uint8_t* creds_out, int creds_out_cap, int* n_creds_out) {
    if (!iparams_bytes || !resp_bytes || !val_bytes || !creds_out || !n_creds_out) {
        return WABISABI_ERR_NULL_PTR;
    }

    /* n_issued byte + at least that many MACs (validated after reading count) */
    if (resp_len < 1) {
        return WABISABI_ERR_INVALID_LENGTH;
    }

    wabisabi_iparams_t ip;
    if (read_ge(iparams_bytes, &ip.cw) < 0 ||
        read_ge(iparams_bytes + WABISABI_GE_SIZE, &ip.i) < 0) {
        return WABISABI_ERR_PARSE;
    }

    /* Build a minimal client state with just iparams (range_proof_width unused in handle_response) */
    wabisabi_client_state_t client;
    client.iparams = ip;
    client.range_proof_width = 0;

    wabisabi_response_validation_t val;
    if (read_validation_state(val_bytes, &val) < 0) {
        return WABISABI_ERR_PARSE;
    }

    wabisabi_response_t resp;
    int off = 0;
    resp.n_issued = resp_bytes[off++];
    if (resp.n_issued != 0 && resp.n_issued != WABISABI_CREDENTIAL_COUNT) {
        return WABISABI_ERR_INVALID_CRED_COUNT;
    }
    if (creds_out_cap < resp.n_issued * WABISABI_CREDENTIAL_SIZE) {
        return WABISABI_ERR_BUFFER_TOO_SMALL;
    }
    for (int i = 0; i < resp.n_issued; i++) {
        int n = read_mac(resp_bytes + off, resp_len - off, &resp.issued[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }
    for (int i = 0; i < resp.n_issued; i++) {
        int n = read_proof(resp_bytes + off, resp_len - off, &resp.proofs[i]);
        if (n < 0) return WABISABI_ERR_PARSE;
        off += n;
    }

    wabisabi_credential_t creds[WABISABI_CREDENTIAL_COUNT];
    wabisabi_error_t err = wabisabi_client_state_handle_response(&client, &resp, &val, creds);
    if (err != WABISABI_OK) {
        secure_zero(creds, sizeof(creds));
        return err;
    }

    for (int i = 0; i < resp.n_issued; i++) {
        write_credential(creds_out + i * WABISABI_CREDENTIAL_SIZE, &creds[i]);
    }

    secure_zero(creds, sizeof(creds));
    *n_creds_out = resp.n_issued;
    return WABISABI_OK;
}
