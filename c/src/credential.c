/* Credential operations */
#include "credential.h"
#include "generators.h"

void
wabisabi_compute_z(wabisabi_ge_t* z_out, const wabisabi_presentation_t* p, const wabisabi_sk_t* sk) {
    /* Z = CV - (w*Gw + x0*Cx0 + x1*Cx1 + ya*Ca) */
    wabisabi_ge_t wGw, x0Cx0, x1Cx1, yaCa, sum;
    wabisabi_ge_mul(&wGw, &sk->w, &WABISABI_Gw);
    wabisabi_ge_mul(&x0Cx0, &sk->x0, &p->cx0);
    wabisabi_ge_mul(&x1Cx1, &sk->x1, &p->cx1);
    wabisabi_ge_mul(&yaCa, &sk->ya, &p->ca);

    wabisabi_ge_add(&sum, &wGw, &x0Cx0);
    wabisabi_ge_add(&sum, &sum, &x1Cx1);
    wabisabi_ge_add(&sum, &sum, &yaCa);

    wabisabi_ge_sub(z_out, &p->cv, &sum);
}
