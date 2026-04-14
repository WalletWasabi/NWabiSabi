/* MAC computation — matches C# Mac.cs and CredentialIssuerSecretKey.cs */
#include "mac.h"
#include <string.h>
#include "generators.h"

void
wabisabi_compute_iparams(wabisabi_iparams_t* out, const wabisabi_sk_t* sk) {
    /* Cw = w*Gw + w'*Gwp */
    wabisabi_ge_t wGw, wpGwp;
    wabisabi_ge_mul(&wGw, &sk->w, &WABISABI_Gw);
    wabisabi_ge_mul(&wpGwp, &sk->wp, &WABISABI_Gwp);
    wabisabi_ge_add(&out->cw, &wGw, &wpGwp);

    /* I = GV - (x0*Gx0 + x1*Gx1 + ya*Ga) */
    wabisabi_ge_t x0Gx0, x1Gx1, yaGa, sum;
    wabisabi_ge_mul(&x0Gx0, &sk->x0, &WABISABI_Gx0);
    wabisabi_ge_mul(&x1Gx1, &sk->x1, &WABISABI_Gx1);
    wabisabi_ge_mul(&yaGa, &sk->ya, &WABISABI_Ga);

    wabisabi_ge_add(&sum, &x0Gx0, &x1Gx1);
    wabisabi_ge_add(&sum, &sum, &yaGa);

    wabisabi_ge_sub(&out->i, &WABISABI_GV, &sum);
}

void
wabisabi_mac_get_u(wabisabi_ge_t* u, const wabisabi_mac_t* mac) {
    wabisabi_generate_u(u, &mac->t);
}

void
wabisabi_mac_compute(wabisabi_mac_t* out, const wabisabi_sk_t* sk, const wabisabi_ge_t* ma,
                     const wabisabi_scalar_t* t) {
    /* MAC(sk, ma, t):
   *   U  = hash_to_curve(t)
   *   m  = w*Gw + ya*ma      (the "message" in the algebraic MAC)
   *   V  = (x0 + x1*t) * U + m
   */
    out->t = *t;

    wabisabi_ge_t U;
    wabisabi_generate_u(&U, t);

    /* x1t = x1 * t */
    wabisabi_scalar_t x1t;
    wabisabi_scalar_mul(&x1t, &sk->x1, t);

    /* coeff = x0 + x1*t */
    wabisabi_scalar_t coeff;
    wabisabi_scalar_add(&coeff, &sk->x0, &x1t);

    /* coeffU = coeff * U */
    wabisabi_ge_t coeffU;
    wabisabi_ge_mul(&coeffU, &coeff, &U);

    /* m = w*Gw + ya*ma */
    wabisabi_ge_t wGw, yaMa, m;
    wabisabi_ge_mul(&wGw, &sk->w, &WABISABI_Gw);
    wabisabi_ge_mul(&yaMa, &sk->ya, ma);
    wabisabi_ge_add(&m, &wGw, &yaMa);

    /* V = coeffU + m */
    wabisabi_ge_add(&out->v, &coeffU, &m);
}
