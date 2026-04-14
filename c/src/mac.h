/* KVAC (Keyed-Verification Anonymous Credential) MAC.
 * Matches WabiSabi/Crypto/Mac.cs.
 */
#pragma once
#include "wabisabi_types.h"

/* Issuer secret key: five scalars (w, w', x0, x1, ya) */
typedef struct {
    wabisabi_scalar_t w, wp, x0, x1, ya;
} wabisabi_sk_t;

/* Public parameters derived from secret key */
typedef struct {
    wabisabi_ge_t cw; /* w*Gw + w'*Gwp */
    wabisabi_ge_t i;  /* GV - (x0*Gx0 + x1*Gx1 + ya*Ga) */
} wabisabi_iparams_t;

/* Algebraic MAC: (t, V) where U = hash_to_curve(t), V = (x0 + x1*t)*U + m */
typedef struct {
    wabisabi_scalar_t t;
    wabisabi_ge_t v;
    /* U is recomputed on demand from t */
} wabisabi_mac_t;

/* Compute public parameters from secret key */
void wabisabi_compute_iparams(wabisabi_iparams_t* out, const wabisabi_sk_t* sk);

/* Compute a MAC on attribute point ma with randomness t */
void wabisabi_mac_compute(wabisabi_mac_t* out, const wabisabi_sk_t* sk, const wabisabi_ge_t* ma,
                          const wabisabi_scalar_t* t);

/* Get U = hash_to_curve(t) */
void wabisabi_mac_get_u(wabisabi_ge_t* u, const wabisabi_mac_t* mac);
