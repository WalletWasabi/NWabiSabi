/* Proof system — matches ProofSystem.cs, Equation.cs, Statement.cs,
 * Knowledge.cs */
#include "proof.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "generators.h"
#include "sha256.h"

/* ---- Equation verify: R + c*P == sum(s_i * G_i) ---- */
static int
equation_verify(const wabisabi_equation_t* eq, const wabisabi_ge_t* pub_nonce, const wabisabi_scalar_t* challenge,
                const wabisabi_scalar_t* responses) {
    if (wabisabi_scalar_is_zero(challenge)) {
        return 0;
    }

    /* LHS: responses * generators */
    wabisabi_ge_t lhs;
    wabisabi_ge_multiscalar(&lhs, responses, eq->generators, eq->n_gen);

    /* RHS: pub_nonce + challenge * public_point */
    wabisabi_ge_t cP;
    wabisabi_ge_mul(&cP, challenge, &eq->public_point);
    wabisabi_ge_t rhs;
    wabisabi_ge_add(&rhs, pub_nonce, &cP);

    return wabisabi_ge_equal(&lhs, &rhs);
}

/* ---- Public nonce for one equation: R_i = sum(nonce_j * G_{i,j}) ---- */
static void
compute_public_nonce(wabisabi_ge_t* out, const wabisabi_equation_t* eq, const wabisabi_scalar_t* secret_nonces) {
    wabisabi_ge_multiscalar(out, secret_nonces, eq->generators, eq->n_gen);
}

/* ---- Prove ---- */
void
wabisabi_prove(wabisabi_proof_t* out, wabisabi_transcript_t* transcript, const wabisabi_knowledge_t* knowledge, int n,
               const uint8_t* random_bytes, size_t rnd_len) {
    /* Step 1: commit all statements to transcript */
    for (int k = 0; k < n; k++) {
        const wabisabi_statement_t* stmt = &knowledge[k].statement;

        /* Collect all public points and generators across all equations */
        /* C# does: statement.PublicPoints ++ statement.Generators */
        static wabisabi_ge_t pub_pts[PROOF_MAX_EQUATIONS];
        static wabisabi_ge_t gens[PROOF_MAX_EQUATIONS * PROOF_MAX_WITNESSES];
        int n_pub = 0, n_gen = 0;
        for (int e = 0; e < stmt->n_equations; e++) {
            pub_pts[n_pub++] = stmt->equations[e].public_point;
            for (int g = 0; g < stmt->n_witnesses; g++) {
                gens[n_gen++] = stmt->equations[e].generators[g];
            }
        }
        wabisabi_transcript_commit_statement(transcript, pub_pts, n_pub, gens, n_gen);
    }

    /* Step 2: for each knowledge, generate secret nonces and public nonces */
    wabisabi_scalar_t all_secret_nonces[PROOF_MAX_WITNESSES]; /* per-witness nonces */
    wabisabi_ge_t all_public_nonces[PROOF_MAX_EQUATIONS];

    for (int k = 0; k < n; k++) {
        const wabisabi_knowledge_t* kn = &knowledge[k];
        int n_wit = kn->statement.n_witnesses;
        int n_eq = kn->statement.n_equations;

        /* Initialize synthetic nonce provider from cloned transcript + secrets */
        wabisabi_nonce_provider_t np;
        wabisabi_nonce_provider_init(&np, transcript, kn->witness, n_wit, random_bytes, rnd_len);

        wabisabi_nonce_provider_fill(all_secret_nonces, n_wit, &np);

        /* Compute public nonces: R_i = sum(nonce_j * G_{i,j}) */
        for (int e = 0; e < n_eq; e++) {
            compute_public_nonce(&all_public_nonces[e], &kn->statement.equations[e], all_secret_nonces);
        }

        /* Commit public nonces to transcript */
        wabisabi_transcript_commit_nonces(transcript, all_public_nonces, n_eq);

        /* Store nonces for later response computation */
        out[k].n_nonces = n_eq;
        out[k].n_responses = n_wit;
        memcpy(out[k].public_nonces, all_public_nonces, n_eq * sizeof(wabisabi_ge_t));
        /* Store secret nonces temporarily in responses (overwritten below) */
        memcpy(out[k].responses, all_secret_nonces, n_wit * sizeof(wabisabi_scalar_t));
    }

    /* Step 3: generate challenge */
    wabisabi_scalar_t challenge;
    wabisabi_transcript_challenge(&challenge, transcript);

    /* Step 4: compute responses: s_j = nonce_j + challenge * witness_j */
    for (int k = 0; k < n; k++) {
        const wabisabi_knowledge_t* kn = &knowledge[k];
        int n_wit = kn->statement.n_witnesses;
        /* out[k].responses currently holds secret nonces */
        for (int j = 0; j < n_wit; j++) {
            wabisabi_scalar_t cw;
            wabisabi_scalar_mul(&cw, &challenge, &kn->witness[j]);
            wabisabi_scalar_add(&out[k].responses[j], &out[k].responses[j], &cw);
        }
    }
}

/* ---- Verify ---- */
int
wabisabi_verify(wabisabi_transcript_t* transcript, const wabisabi_statement_t* statements, int n_stmt,
                const wabisabi_proof_t* proofs, int n_proof) {
    if (n_stmt != n_proof) {
        return 0;
    }

    /* Step 1: commit all statements */
    for (int k = 0; k < n_stmt; k++) {
        const wabisabi_statement_t* stmt = &statements[k];
        static wabisabi_ge_t pub_pts[PROOF_MAX_EQUATIONS];
        static wabisabi_ge_t gens[PROOF_MAX_EQUATIONS * PROOF_MAX_WITNESSES];
        int n_pub = 0, n_gen = 0;
        for (int e = 0; e < stmt->n_equations; e++) {
            pub_pts[n_pub++] = stmt->equations[e].public_point;
            for (int g = 0; g < stmt->n_witnesses; g++) {
                gens[n_gen++] = stmt->equations[e].generators[g];
            }
        }
        wabisabi_transcript_commit_statement(transcript, pub_pts, n_pub, gens, n_gen);
    }

    /* Step 2: commit all public nonces */
    for (int k = 0; k < n_proof; k++) {
        wabisabi_transcript_commit_nonces(transcript, proofs[k].public_nonces, proofs[k].n_nonces);
    }

    /* Step 3: generate challenge */
    wabisabi_scalar_t challenge;
    wabisabi_transcript_challenge(&challenge, transcript);

    /* Step 4: verify each equation */
    for (int k = 0; k < n_stmt; k++) {
        const wabisabi_statement_t* stmt = &statements[k];
        if (stmt->n_equations != proofs[k].n_nonces) {
            return 0;
        }
        for (int e = 0; e < stmt->n_equations; e++) {
            if (!equation_verify(&stmt->equations[e], &proofs[k].public_nonces[e], &challenge, proofs[k].responses)) {
                return 0;
            }
        }
    }
    return 1;
}

/* ---- Pedersen commitment ---- */
void
wabisabi_pedersen_commit(wabisabi_ge_t* out, const wabisabi_scalar_t* amount, const wabisabi_scalar_t* randomness) {
    wabisabi_scalar_t sc[2] = {*amount, *randomness};
    wabisabi_ge_t ge[2] = {WABISABI_Gg, WABISABI_Gh};
    wabisabi_ge_multiscalar(out, sc, ge, 2);
}

/* ---- Infinity (zero generator) ---- */
static wabisabi_ge_t GE_INFINITY = {.is_infinity = 1};

/* ---- IssuerParameters statement & knowledge ---- */

wabisabi_statement_t
wabisabi_issuer_params_statement(const wabisabi_iparams_t* iparams, const wabisabi_mac_t* mac,
                                 const wabisabi_ge_t* ma) {
    wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.n_equations = 3;
    stmt.n_witnesses = 5; /* w, wp, x0, x1, ya */

    wabisabi_ge_t U;
    wabisabi_mac_get_u(&U, mac);

    wabisabi_scalar_t t_scalar = mac->t;
    wabisabi_ge_t tU;
    wabisabi_ge_mul(&tU, &t_scalar, &U);

    /* Equation 0: mac.V = w*Gw + 0*Gwp + x0*U + x1*(t*U) + ya*ma */
    stmt.equations[0].public_point = mac->v;
    stmt.equations[0].generators[0] = WABISABI_Gw;
    stmt.equations[0].generators[1] = GE_INFINITY;
    stmt.equations[0].generators[2] = U;
    stmt.equations[0].generators[3] = tU;
    stmt.equations[0].generators[4] = *ma;
    stmt.equations[0].n_gen = 5;

    /* Equation 1: GV - iparams.I = 0*Gw + 0*Gwp + x0*Gx0 + x1*Gx1 + ya*Ga */
    wabisabi_ge_sub(&stmt.equations[1].public_point, &WABISABI_GV, &iparams->i);
    stmt.equations[1].generators[0] = GE_INFINITY;
    stmt.equations[1].generators[1] = GE_INFINITY;
    stmt.equations[1].generators[2] = WABISABI_Gx0;
    stmt.equations[1].generators[3] = WABISABI_Gx1;
    stmt.equations[1].generators[4] = WABISABI_Ga;
    stmt.equations[1].n_gen = 5;

    /* Equation 2: iparams.Cw = w*Gw + wp*Gwp + 0*Gx0 + 0*Gx1 + 0*Ga */
    stmt.equations[2].public_point = iparams->cw;
    stmt.equations[2].generators[0] = WABISABI_Gw;
    stmt.equations[2].generators[1] = WABISABI_Gwp;
    stmt.equations[2].generators[2] = GE_INFINITY;
    stmt.equations[2].generators[3] = GE_INFINITY;
    stmt.equations[2].generators[4] = GE_INFINITY;
    stmt.equations[2].n_gen = 5;

    return stmt;
}

void
wabisabi_issuer_params_knowledge(wabisabi_knowledge_t* out, const wabisabi_mac_t* mac, const wabisabi_ge_t* ma,
                                 const wabisabi_sk_t* sk) {
    wabisabi_iparams_t iparams;
    wabisabi_compute_iparams(&iparams, sk);
    out->statement = wabisabi_issuer_params_statement(&iparams, mac, ma);
    out->witness[0] = sk->w;
    out->witness[1] = sk->wp;
    out->witness[2] = sk->x0;
    out->witness[3] = sk->x1;
    out->witness[4] = sk->ya;
}

/* ---- Credential presentation (randomization) ---- */

wabisabi_presentation_t
wabisabi_credential_present(const wabisabi_mac_t* mac, int64_t value, const wabisabi_scalar_t* randomness,
                            const wabisabi_scalar_t* z) {
    /* Ca  = ma + z*Ga   where ma = value*Gg + randomness*Gh */
    /* Cx0 = U  + z*Gx0 */
    /* Cx1 = tU + z*Gx1  where tU = t * U */
    /* CV  = V  + z*GV */
    /* S   = randomness * Gs */

    wabisabi_presentation_t p;

    uint8_t val_bytes[WABISABI_SCALAR_SIZE] = {0};
    uint64_t uval = (uint64_t)value;
    for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
        val_bytes[31 - i] = (uint8_t)(uval >> (8 * i));
    }
    wabisabi_scalar_t val_scalar;
    memcpy(val_scalar.data, val_bytes, WABISABI_SCALAR_SIZE);

    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, &val_scalar, randomness);
    wabisabi_ge_t U;
    wabisabi_mac_get_u(&U, mac);

    wabisabi_scalar_t t = mac->t;
    wabisabi_ge_t tU;
    wabisabi_ge_mul(&tU, &t, &U);

    /* Ca = ma + z*Ga */
    wabisabi_ge_t zGa;
    wabisabi_ge_mul(&zGa, z, &WABISABI_Ga);
    wabisabi_ge_add(&p.ca, &ma, &zGa);

    /* Cx0 = U + z*Gx0 */
    wabisabi_ge_t zGx0;
    wabisabi_ge_mul(&zGx0, z, &WABISABI_Gx0);
    wabisabi_ge_add(&p.cx0, &U, &zGx0);

    /* Cx1 = tU + z*Gx1 */
    wabisabi_ge_t zGx1;
    wabisabi_ge_mul(&zGx1, z, &WABISABI_Gx1);
    wabisabi_ge_add(&p.cx1, &tU, &zGx1);

    /* CV = V + z*GV */
    wabisabi_ge_t zGV;
    wabisabi_ge_mul(&zGV, z, &WABISABI_GV);
    wabisabi_ge_add(&p.cv, &mac->v, &zGV);

    /* S = randomness * Gs */
    wabisabi_ge_mul(&p.s, randomness, &WABISABI_Gs);

    return p;
}

/* ---- ShowCredential statement & knowledge ---- */

wabisabi_statement_t
wabisabi_show_credential_statement(const wabisabi_presentation_t* p, const wabisabi_ge_t* z_point,
                                   const wabisabi_iparams_t* iparams) {
    wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.n_equations = 4;
    stmt.n_witnesses = 5; /* z, z0=-t*z, t, a, r */

    /* Equation 0: z_point = z*I + 0*Gx0 + 0*Cx0 + 0*Gg + 0*Gh */
    stmt.equations[0].public_point = *z_point;
    stmt.equations[0].generators[0] = iparams->i;
    stmt.equations[0].generators[1] = GE_INFINITY;
    stmt.equations[0].generators[2] = GE_INFINITY;
    stmt.equations[0].generators[3] = GE_INFINITY;
    stmt.equations[0].generators[4] = GE_INFINITY;
    stmt.equations[0].n_gen = 5;

    /* Equation 1: Cx1 = z0*Gx0 + z*Gx1 + t*Cx0 + 0*Gg + 0*Gh
   * (Witnesses: z, z0, t, a, r  →  generators: Gx1, Gx0, Cx0, O, O) */
    stmt.equations[1].public_point = p->cx1;
    stmt.equations[1].generators[0] = WABISABI_Gx1;
    stmt.equations[1].generators[1] = WABISABI_Gx0;
    stmt.equations[1].generators[2] = p->cx0;
    stmt.equations[1].generators[3] = GE_INFINITY;
    stmt.equations[1].generators[4] = GE_INFINITY;
    stmt.equations[1].n_gen = 5;

    /* Equation 2: Ca = z*Ga + 0*Gx0 + 0*Cx0 + a*Gg + r*Gh */
    stmt.equations[2].public_point = p->ca;
    stmt.equations[2].generators[0] = WABISABI_Ga;
    stmt.equations[2].generators[1] = GE_INFINITY;
    stmt.equations[2].generators[2] = GE_INFINITY;
    stmt.equations[2].generators[3] = WABISABI_Gg;
    stmt.equations[2].generators[4] = WABISABI_Gh;
    stmt.equations[2].n_gen = 5;

    /* Equation 3: S = 0*Ga + 0*Gx0 + 0*Cx0 + 0*Gg + r*Gs
   * (actually: S = r*Gs, witness index 4 = r) */
    stmt.equations[3].public_point = p->s;
    stmt.equations[3].generators[0] = GE_INFINITY;
    stmt.equations[3].generators[1] = GE_INFINITY;
    stmt.equations[3].generators[2] = GE_INFINITY;
    stmt.equations[3].generators[3] = GE_INFINITY;
    stmt.equations[3].generators[4] = WABISABI_Gs;
    stmt.equations[3].n_gen = 5;

    return stmt;
}

wabisabi_knowledge_t
wabisabi_show_credential_knowledge(const wabisabi_presentation_t* p, const wabisabi_scalar_t* z,
                                   const wabisabi_mac_t* mac, int64_t value, const wabisabi_scalar_t* randomness,
                                   const wabisabi_iparams_t* iparams) {
    /* z_point = z * I */
    wabisabi_ge_t z_point;
    wabisabi_ge_mul(&z_point, z, &iparams->i);

    wabisabi_knowledge_t kn;
    kn.statement = wabisabi_show_credential_statement(p, &z_point, iparams);

    /* Witness: (z, z0 = -(t*z), t, a, r) */
    kn.witness[0] = *z;

    /* z0 = -(t * z) */
    wabisabi_scalar_t tz;
    wabisabi_scalar_mul(&tz, &mac->t, z);
    wabisabi_scalar_negate(&kn.witness[1], &tz);

    kn.witness[2] = mac->t;

    /* a = value as scalar */
    uint8_t val_bytes[WABISABI_SCALAR_SIZE] = {0};
    uint64_t uval = (uint64_t)value;
    for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
        val_bytes[31 - i] = (uint8_t)(uval >> (8 * i));
    }
    memcpy(kn.witness[3].data, val_bytes, WABISABI_SCALAR_SIZE);

    kn.witness[4] = *randomness;

    return kn;
}

/* ---- Balance proof ---- */

wabisabi_statement_t
wabisabi_balance_proof_statement(const wabisabi_ge_t* balance_commitment) {
    wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.n_equations = 1;
    stmt.n_witnesses = 2; /* z_sum, r_delta_sum */

    stmt.equations[0].public_point = *balance_commitment;
    stmt.equations[0].generators[0] = WABISABI_Ga;
    stmt.equations[0].generators[1] = WABISABI_Gh;
    stmt.equations[0].n_gen = 2;
    return stmt;
}

wabisabi_knowledge_t
wabisabi_balance_proof_knowledge(const wabisabi_scalar_t* z_sum, const wabisabi_scalar_t* r_delta_sum) {
    /* Balance commitment = z_sum*Ga + r_delta_sum*Gh */
    wabisabi_knowledge_t kn;

    wabisabi_ge_t zGa, rGh;
    wabisabi_ge_mul(&zGa, z_sum, &WABISABI_Ga);
    wabisabi_ge_mul(&rGh, r_delta_sum, &WABISABI_Gh);
    wabisabi_ge_t bc;
    wabisabi_ge_add(&bc, &zGa, &rGh);

    kn.statement = wabisabi_balance_proof_statement(&bc);
    kn.witness[0] = *z_sum;
    kn.witness[1] = *r_delta_sum;
    return kn;
}

/* ---- Zero proof (bootstrap) ---- */

wabisabi_statement_t
wabisabi_zero_proof_statement(const wabisabi_ge_t* ma) {
    return wabisabi_range_proof_statement(ma, NULL, 0);
}

wabisabi_knowledge_t
wabisabi_zero_proof_knowledge(const wabisabi_ge_t* ma, const wabisabi_scalar_t* r) {
    wabisabi_knowledge_t kn;
    kn.statement = wabisabi_zero_proof_statement(ma);
    kn.witness[0] = *r;
    return kn;
}

/* ---- Range proof ---- */

wabisabi_statement_t
wabisabi_range_proof_statement(const wabisabi_ge_t* ma, const wabisabi_ge_t* bit_commitments, int width) {
    assert(width >= 0 && width <= WABISABI_MAX_RANGE_WIDTH);

    wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));

    /* rows = 2*width + 1 (or 1 if width==0) */
    stmt.n_equations = width * 2 + 1;
    /* columns = 3*width + 1 (witnesses) */
    stmt.n_witnesses = width * 3 + 1;

    /* memset leaves is_infinity=0 with zeroed pk — an invalid state.
   * Initialize all generator slots to GE_INFINITY before filling specific ones.
   */
    for (int e = 0; e < stmt.n_equations; e++) {
        stmt.equations[e].public_point = GE_INFINITY;
        for (int g = 0; g < stmt.n_witnesses; g++) {
            stmt.equations[e].generators[g] = GE_INFINITY;
        }
    }

    /* Helper indices (matching C# static functions) */
    /* BitColumn(i) = 3*i + 2 (1-indexed in the C# code, but witnesses are
   * 0-indexed here) In C#: static int BitColumn(int i) => 3 * i + 2;  // in
   * RangeProofStatement static int RndColumn(int i) => BitColumn(i) + 1; static
   * int ProductColumn(int i) => BitColumn(i) + 2; The "+1" comes from the first
   * column being the "public input" which is the generator for the r
   * (randomness) witness. In our system, witnesses are 0-indexed: witness[0] =
   * r witness[3*i+1] = b_i witness[3*i+2] = r_i witness[3*i+3] = rb_i = r_i *
   * b_i
   */
#define BIT_COL(i)  (3 * (i) + 1)
#define RND_COL(i)  (BIT_COL(i) + 1)
#define PROD_COL(i) (BIT_COL(i) + 2)
#define BIT_ROW(i)  (2 * (i) + 1)
#define BITS_ROW(i) (BIT_ROW(i) + 1)

    /* Compute bitsTotal = sum(2^i * B_i) for i=0..width-1 */
    wabisabi_ge_t bits_total = GE_INFINITY;
    for (int i = 0; i < width; i++) {
        wabisabi_ge_t term;
        wabisabi_ge_mul(&term, &WABISABI_POW2[i], &bit_commitments[i]);
        wabisabi_ge_add(&bits_total, &bits_total, &term);
    }

    /* Equation 0: (ma - bitsTotal) = r*Gh + sum(-2^i * r_i) * Gh
   * public_point = ma - bitsTotal */
    wabisabi_ge_sub(&stmt.equations[0].public_point, ma, &bits_total);
    stmt.equations[0].generators[0] = WABISABI_Gh; /* witness[0] = r */
    for (int i = 0; i < width; i++) {
        stmt.equations[0].generators[RND_COL(i)] = WABISABI_NEG_GH_POW2[i];
    }
    stmt.equations[0].n_gen = stmt.n_witnesses;

    for (int i = 0; i < width; i++) {
        /* Equation BIT_ROW(i): B_i = b_i*Gg + r_i*Gh */
        stmt.equations[BIT_ROW(i)].public_point = bit_commitments[i];
        stmt.equations[BIT_ROW(i)].generators[BIT_COL(i)] = WABISABI_Gg;
        stmt.equations[BIT_ROW(i)].generators[RND_COL(i)] = WABISABI_Gh;
        stmt.equations[BIT_ROW(i)].n_gen = stmt.n_witnesses;

        /* Equation BITS_ROW(i): O = b_i*(B_i - Gg) + (-rb_i)*Gh
     * This proves b_i is a bit (b_i = b_i^2) */
        stmt.equations[BITS_ROW(i)].public_point = GE_INFINITY; /* O */
        wabisabi_ge_t Bi_minus_Gg;
        wabisabi_ge_sub(&Bi_minus_Gg, &bit_commitments[i], &WABISABI_Gg);
        stmt.equations[BITS_ROW(i)].generators[BIT_COL(i)] = Bi_minus_Gg;
        wabisabi_ge_t neg_Gh;
        wabisabi_ge_negate(&neg_Gh, &WABISABI_Gh);
        stmt.equations[BITS_ROW(i)].generators[PROD_COL(i)] = neg_Gh;
        stmt.equations[BITS_ROW(i)].n_gen = stmt.n_witnesses;
    }

#undef BIT_COL
#undef RND_COL
#undef PROD_COL
#undef BIT_ROW
#undef BITS_ROW

    return stmt;
}

wabisabi_range_proof_t
wabisabi_range_proof_knowledge(const wabisabi_scalar_t* amount, const wabisabi_scalar_t* randomness, int width,
                               const uint8_t* random_bytes, size_t rnd_len) {
    assert(width >= 0 && width <= WABISABI_MAX_RANGE_WIDTH);

    wabisabi_range_proof_t rp;
    rp.width = width;

    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, amount, randomness);

    /* Derive bit randomness from the random bytes using a simple hash */
    /* (The C# code calls rnd.GetScalar() for each bit) */
    wabisabi_scalar_t bit_randomness[WABISABI_MAX_RANGE_WIDTH];
    {
        /* Use SHA-256 chain to derive bit randomnesses */
        uint8_t seed[WABISABI_SCALAR_SIZE];
        memcpy(seed, random_bytes, rnd_len < WABISABI_SCALAR_SIZE ? rnd_len : WABISABI_SCALAR_SIZE);
        for (int i = 0; i < width; i++) {
            sha256(seed, WABISABI_SCALAR_SIZE, seed);
            /* Try until valid scalar */
            while (!secp256k1_ec_seckey_verify(WABISABI_CTX, seed)) {
                sha256(seed, WABISABI_SCALAR_SIZE, seed);
            }
            memcpy(bit_randomness[i].data, seed, WABISABI_SCALAR_SIZE);
        }
    }

    /* Compute bit commitments */
    for (int i = 0; i < width; i++) {
        int b = wabisabi_scalar_get_bit(amount, i); /* bit i from LSB */
        wabisabi_scalar_t b_scalar = b ? WABISABI_SCALAR_ONE : WABISABI_SCALAR_ZERO;
        wabisabi_pedersen_commit(&rp.bit_commitments[i], &b_scalar, &bit_randomness[i]);
    }

    rp.knowledge.statement = wabisabi_range_proof_statement(&ma, rp.bit_commitments, width);
    rp.knowledge.statement.n_witnesses = width * 3 + 1;

#define BIT_COL(i)  (3 * (i) + 1)
#define RND_COL(i)  (BIT_COL(i) + 1)
#define PROD_COL(i) (BIT_COL(i) + 2)

    /* witness[0] = r */
    rp.knowledge.witness[0] = *randomness;

    for (int i = 0; i < width; i++) {
        int b = wabisabi_scalar_get_bit(amount, i);
        wabisabi_scalar_t b_scalar = b ? WABISABI_SCALAR_ONE : WABISABI_SCALAR_ZERO;

        rp.knowledge.witness[BIT_COL(i)] = b_scalar;
        rp.knowledge.witness[RND_COL(i)] = bit_randomness[i];

        /* rb_i = r_i * b_i */
        wabisabi_scalar_mul(&rp.knowledge.witness[PROD_COL(i)], &bit_randomness[i], &b_scalar);
    }

#undef BIT_COL
#undef RND_COL
#undef PROD_COL

    return rp;
}
