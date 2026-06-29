/* Core types for WabiSabi C implementation.
 * Scalars and group elements wrap secp256k1 public API types.
 */
#pragma once
#include <secp256k1.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Protocol constants */
#define WABISABI_CREDENTIAL_COUNT  2
#define WABISABI_MAX_RANGE_WIDTH   51 /* bits; supports the full 21M BTC supply */

/* Wire-format sizes */
#define WABISABI_SCALAR_SIZE       32                                        /* secp256k1 scalar, big-endian */
#define WABISABI_GE_SIZE           33                                        /* compressed secp256k1 point */
#define WABISABI_VALUE_SIZE        8                                         /* 8-byte LE amount field */
#define WABISABI_MAC_SIZE          (WABISABI_SCALAR_SIZE + WABISABI_GE_SIZE) /* t + V */
#define WABISABI_PRESENTATION_SIZE (5 * WABISABI_GE_SIZE)                    /* Ca Cx0 Cx1 CV S */
#define WABISABI_CREDENTIAL_SIZE                                                                                       \
    (WABISABI_VALUE_SIZE + WABISABI_SCALAR_SIZE + WABISABI_MAC_SIZE) /* value + randomness + mac   \
                                                                      */

/* ---- Scalar -------------------------------------------------------
 * 32-byte big-endian, range [0, n).  All-zero = scalar zero.
 * secp256k1 curve order n =
 *   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 */
typedef struct {
    uint8_t data[WABISABI_SCALAR_SIZE];
} wabisabi_scalar_t;

_Static_assert(WABISABI_SCALAR_SIZE == 32, "scalar size must be 32");
_Static_assert(WABISABI_GE_SIZE == 33, "GE size must be 33");
_Static_assert(WABISABI_VALUE_SIZE == 8, "value size must be 8");

/* ---- Group Element ------------------------------------------------
 * secp256k1_pubkey is 64 bytes of opaque compressed affine data.
 * is_infinity flag handles the point at infinity (secp256k1 API can't).
 */
typedef struct {
    secp256k1_pubkey pk;
    int is_infinity;
} wabisabi_ge_t;

/* Global secp256k1 context — call wabisabi_ctx_init() once */
extern secp256k1_context* WABISABI_CTX;

/* ---- Scalar operations ------------------------------------------- */
static inline int
wabisabi_scalar_is_zero(const wabisabi_scalar_t* s) {
    uint8_t acc = 0;
    for (int i = 0; i < WABISABI_SCALAR_SIZE; i++) {
        acc |= s->data[i];
    }
    return acc == 0;
}

/* r = a + b mod n */
int wabisabi_scalar_add(wabisabi_scalar_t* r, const wabisabi_scalar_t* a, const wabisabi_scalar_t* b);

/* r = a * b mod n */
int wabisabi_scalar_mul(wabisabi_scalar_t* r, const wabisabi_scalar_t* a, const wabisabi_scalar_t* b);

/* r = -a mod n */
int wabisabi_scalar_negate(wabisabi_scalar_t* r, const wabisabi_scalar_t* a);

/* Get bit i (from LSB, 0-indexed) of scalar */
int wabisabi_scalar_get_bit(const wabisabi_scalar_t* s, int i);

/* ---- Group element operations ------------------------------------ */

/* r = a + b */
void wabisabi_ge_add(wabisabi_ge_t* r, const wabisabi_ge_t* a, const wabisabi_ge_t* b);

/* r = -a */
void wabisabi_ge_negate(wabisabi_ge_t* r, const wabisabi_ge_t* a);

/* r = scalar * point */
void wabisabi_ge_mul(wabisabi_ge_t* r, const wabisabi_scalar_t* s, const wabisabi_ge_t* p);

/* r = scalar * G (secp256k1 base point) */
void wabisabi_ge_mul_base(wabisabi_ge_t* r, const wabisabi_scalar_t* s);

/* r = sum_i(scalars[i] * points[i]) */
void wabisabi_ge_multiscalar(wabisabi_ge_t* r, const wabisabi_scalar_t* scalars, const wabisabi_ge_t* points, size_t n);

/* r = a - b */
static inline void
wabisabi_ge_sub(wabisabi_ge_t* r, const wabisabi_ge_t* a, const wabisabi_ge_t* b) {
    wabisabi_ge_t nb;
    wabisabi_ge_negate(&nb, b);
    wabisabi_ge_add(r, a, &nb);
}

/* Equality check */
int wabisabi_ge_equal(const wabisabi_ge_t* a, const wabisabi_ge_t* b);

/* Serialize to WABISABI_GE_SIZE-byte compressed form */
void wabisabi_ge_serialize(uint8_t out[WABISABI_GE_SIZE], const wabisabi_ge_t* p);

/* Deserialize from WABISABI_GE_SIZE-byte compressed form. Returns 1 on success. */
int wabisabi_ge_parse(wabisabi_ge_t* p, const uint8_t in[WABISABI_GE_SIZE]);

/* Initialize WabiSabi secp256k1 context. Call once (internal use). */
void wabisabi_ctx_init(void);

/* Free WabiSabi secp256k1 context. */
void wabisabi_ctx_cleanup(void);
