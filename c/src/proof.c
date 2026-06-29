/* Proof system — matches ProofSystem.cs, Equation.cs, Statement.cs,
 * Knowledge.cs
 *
 * Uses SPARSE representation for generator matrices to support large
 * range proof widths (up to 51 bits) without excessive memory usage.
 */
#include "proof.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "generators.h"
#include "sha256.h"

/* ---- Sparse equation operations ---- */

/* Compute R = sum(responses[entry.witness_idx] * entry.generator) for sparse equation */
static void
sparse_multiscalar(wabisabi_ge_t* out, const wabisabi_equation_t* eq, const wabisabi_scalar_t* responses) {
    *out = GE_INFINITY;
    for (int i = 0; i < eq->n_entries; i++) {
        wabisabi_ge_t term;
        wabisabi_ge_mul(&term, &responses[eq->entries[i].witness_idx], &eq->entries[i].generator);
        wabisabi_ge_add(out, out, &term);
    }
}

/* Equation verify: R + c*P == sum(s[idx_i] * G_i) */
static int
equation_verify(const wabisabi_equation_t* eq, const wabisabi_ge_t* pub_nonce, const wabisabi_scalar_t* challenge,
                const wabisabi_scalar_t* responses) {
    if (wabisabi_scalar_is_zero(challenge)) {
        return 0;
    }

    /* LHS: sparse multiscalar with responses */
    wabisabi_ge_t lhs;
    sparse_multiscalar(&lhs, eq, responses);

    /* RHS: pub_nonce + challenge * public_point */
    wabisabi_ge_t cP;
    wabisabi_ge_mul(&cP, challenge, &eq->public_point);
    wabisabi_ge_t rhs;
    wabisabi_ge_add(&rhs, pub_nonce, &cP);

    return wabisabi_ge_equal(&lhs, &rhs);
}

/* Compute public nonce: R = sum(nonce[idx_i] * G_i) for sparse equation */
static void
compute_public_nonce(wabisabi_ge_t* out, const wabisabi_equation_t* eq, const wabisabi_scalar_t* secret_nonces) {
    sparse_multiscalar(out, eq, secret_nonces);
}

/* ---- Prove ---- */
void
wabisabi_prove(wabisabi_proof_t* out, wabisabi_transcript_t* transcript, const wabisabi_knowledge_t* knowledge, int n,
               const uint8_t* random_bytes, size_t rnd_len) {
    /* Step 1: commit all statements to transcript */
    for (int k = 0; k < n; k++) {
        const wabisabi_statement_t* stmt = &knowledge[k].statement;

        /* Collect all public points from equations */
        static wabisabi_ge_t pub_pts[PROOF_MAX_EQUATIONS];
        int n_pub = 0;
        for (int e = 0; e < stmt->n_equations; e++) {
            pub_pts[n_pub++] = stmt->equations[e].public_point;
        }

        /* Collect all generators from sparse entries.
         * For transcript compatibility with C#, we need to serialize
         * the generators in a consistent order. The C# code iterates
         * equations × witnesses densely. For sparse, we expand to dense
         * for the transcript only.
         */
        static wabisabi_ge_t gens[PROOF_MAX_EQUATIONS * PROOF_MAX_WITNESSES];
        int n_gen = 0;
        for (int e = 0; e < stmt->n_equations; e++) {
            /* Build dense row from sparse entries */
            for (int w = 0; w < stmt->n_witnesses; w++) {
                wabisabi_ge_t g = GE_INFINITY;
                /* Find if this witness is in the sparse entries */
                for (int s = 0; s < stmt->equations[e].n_entries; s++) {
                    if (stmt->equations[e].entries[s].witness_idx == w) {
                        g = stmt->equations[e].entries[s].generator;
                        break;
                    }
                }
                gens[n_gen++] = g;
            }
        }
        wabisabi_transcript_commit_statement(transcript, pub_pts, n_pub, gens, n_gen);
    }

    /* Step 2: for each knowledge, generate secret nonces and public nonces */
    static wabisabi_scalar_t all_secret_nonces[PROOF_MAX_WITNESSES];
    static wabisabi_ge_t all_public_nonces[PROOF_MAX_EQUATIONS];

    for (int k = 0; k < n; k++) {
        const wabisabi_knowledge_t* kn = &knowledge[k];
        int n_wit = kn->statement.n_witnesses;
        int n_eq = kn->statement.n_equations;

        /* Initialize synthetic nonce provider from cloned transcript + secrets */
        wabisabi_nonce_provider_t np;
        wabisabi_nonce_provider_init(&np, transcript, kn->witness, n_wit, random_bytes, rnd_len);

        wabisabi_nonce_provider_fill(all_secret_nonces, n_wit, &np);

        /* Compute public nonces: R_i = sum(nonce[idx_j] * G_{i,j}) */
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

    /* Step 1: commit all statements (same as in prove) */
    for (int k = 0; k < n_stmt; k++) {
        const wabisabi_statement_t* stmt = &statements[k];
        static wabisabi_ge_t pub_pts[PROOF_MAX_EQUATIONS];
        static wabisabi_ge_t gens[PROOF_MAX_EQUATIONS * PROOF_MAX_WITNESSES];
        int n_pub = 0, n_gen = 0;
        for (int e = 0; e < stmt->n_equations; e++) {
            pub_pts[n_pub++] = stmt->equations[e].public_point;
        }
        for (int e = 0; e < stmt->n_equations; e++) {
            for (int w = 0; w < stmt->n_witnesses; w++) {
                wabisabi_ge_t g = GE_INFINITY;
                for (int s = 0; s < stmt->equations[e].n_entries; s++) {
                    if (stmt->equations[e].entries[s].witness_idx == w) {
                        g = stmt->equations[e].entries[s].generator;
                        break;
                    }
                }
                gens[n_gen++] = g;
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
    wabisabi_ge_t aG, rH;
    wabisabi_ge_mul(&aG, amount, &WABISABI_Gg);
    wabisabi_ge_mul(&rH, randomness, &WABISABI_Gh);
    wabisabi_ge_add(out, &aG, &rH);
}

/* ---- IssuerParams statement & knowledge ---- */

wabisabi_statement_t
wabisabi_issuer_params_statement(const wabisabi_iparams_t* iparams, const wabisabi_mac_t* mac,
                                  const wabisabi_ge_t* ma) {
    static wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.n_equations = 3;
    stmt.n_witnesses = 5; /* w, wp, x0, x1, ya */

    /* Get U from the MAC */
    wabisabi_ge_t U;
    wabisabi_mac_get_u(&U, mac);

    wabisabi_ge_t tU;
    wabisabi_ge_mul(&tU, &mac->t, &U);

    /* Equation 0: mac.V = w*Gw + x0*U + x1*(t*U) + ya*ma */
    stmt.equations[0].public_point = mac->v;
    stmt.equations[0].n_entries = 0;
    equation_add_entry(&stmt.equations[0], 0, &WABISABI_Gw);
    equation_add_entry(&stmt.equations[0], 2, &U);
    equation_add_entry(&stmt.equations[0], 3, &tU);
    equation_add_entry(&stmt.equations[0], 4, ma);

    /* Equation 1: GV - iparams.I = x0*Gx0 + x1*Gx1 + ya*Ga */
    wabisabi_ge_sub(&stmt.equations[1].public_point, &WABISABI_GV, &iparams->i);
    stmt.equations[1].n_entries = 0;
    equation_add_entry(&stmt.equations[1], 2, &WABISABI_Gx0);
    equation_add_entry(&stmt.equations[1], 3, &WABISABI_Gx1);
    equation_add_entry(&stmt.equations[1], 4, &WABISABI_Ga);

    /* Equation 2: iparams.Cw = w*Gw + wp*Gwp */
    stmt.equations[2].public_point = iparams->cw;
    stmt.equations[2].n_entries = 0;
    equation_add_entry(&stmt.equations[2], 0, &WABISABI_Gw);
    equation_add_entry(&stmt.equations[2], 1, &WABISABI_Gwp);

    return stmt;
}

void
wabisabi_issuer_params_knowledge(wabisabi_knowledge_t* out, const wabisabi_mac_t* mac, const wabisabi_ge_t* ma,
                                  const wabisabi_sk_t* sk) {
    /* Compute iparams from sk */
    wabisabi_iparams_t iparams;
    wabisabi_compute_iparams(&iparams, sk);

    out->statement = wabisabi_issuer_params_statement(&iparams, mac, ma);
    out->witness[0] = sk->w;
    out->witness[1] = sk->wp;
    out->witness[2] = sk->x0;
    out->witness[3] = sk->x1;
    out->witness[4] = sk->ya;
}

/* ---- Credential presentation ---- */

wabisabi_presentation_t
wabisabi_credential_present(const wabisabi_mac_t* mac, int64_t value, const wabisabi_scalar_t* randomness,
                             const wabisabi_scalar_t* z) {
    wabisabi_presentation_t p;

    /* Get U from the MAC */
    wabisabi_ge_t U;
    wabisabi_mac_get_u(&U, mac);

    /* Compute ma = value*Gg + randomness*Gh */
    wabisabi_ge_t ma;
    uint8_t val_bytes[WABISABI_SCALAR_SIZE] = {0};
    uint64_t uval = (uint64_t)value;
    for (int i = 0; i < WABISABI_VALUE_SIZE; i++) {
        val_bytes[31 - i] = (uint8_t)(uval >> (8 * i));
    }
    wabisabi_scalar_t a_scalar;
    memcpy(a_scalar.data, val_bytes, WABISABI_SCALAR_SIZE);
    wabisabi_pedersen_commit(&ma, &a_scalar, randomness);

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
    static wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.n_equations = 4;
    stmt.n_witnesses = 5; /* z, z0=-t*z, t, a, r */

    /* Equation 0: z_point = z*I */
    stmt.equations[0].public_point = *z_point;
    stmt.equations[0].n_entries = 0;
    equation_add_entry(&stmt.equations[0], 0, &iparams->i);

    /* Equation 1: Cx1 = z0*Gx0 + z*Gx1 + t*Cx0 */
    stmt.equations[1].public_point = p->cx1;
    stmt.equations[1].n_entries = 0;
    equation_add_entry(&stmt.equations[1], 0, &WABISABI_Gx1);  /* z */
    equation_add_entry(&stmt.equations[1], 1, &WABISABI_Gx0);  /* z0 */
    equation_add_entry(&stmt.equations[1], 2, &p->cx0);        /* t */

    /* Equation 2: Ca = z*Ga + a*Gg + r*Gh */
    stmt.equations[2].public_point = p->ca;
    stmt.equations[2].n_entries = 0;
    equation_add_entry(&stmt.equations[2], 0, &WABISABI_Ga);  /* z */
    equation_add_entry(&stmt.equations[2], 3, &WABISABI_Gg);  /* a */
    equation_add_entry(&stmt.equations[2], 4, &WABISABI_Gh);  /* r */

    /* Equation 3: S = r*Gs */
    stmt.equations[3].public_point = p->s;
    stmt.equations[3].n_entries = 0;
    equation_add_entry(&stmt.equations[3], 4, &WABISABI_Gs);  /* r */

    return stmt;
}

wabisabi_knowledge_t
wabisabi_show_credential_knowledge(const wabisabi_presentation_t* p, const wabisabi_scalar_t* z,
                                   const wabisabi_mac_t* mac, int64_t value, const wabisabi_scalar_t* randomness,
                                   const wabisabi_iparams_t* iparams) {
    /* z_point = z * I */
    wabisabi_ge_t z_point;
    wabisabi_ge_mul(&z_point, z, &iparams->i);

    static wabisabi_knowledge_t kn;
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
    static wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.n_equations = 1;
    stmt.n_witnesses = 2; /* z_sum, r_delta_sum */

    stmt.equations[0].public_point = *balance_commitment;
    stmt.equations[0].n_entries = 0;
    equation_add_entry(&stmt.equations[0], 0, &WABISABI_Ga);
    equation_add_entry(&stmt.equations[0], 1, &WABISABI_Gh);

    return stmt;
}

wabisabi_knowledge_t
wabisabi_balance_proof_knowledge(const wabisabi_scalar_t* z_sum, const wabisabi_scalar_t* r_delta_sum) {
    /* Balance commitment = z_sum*Ga + r_delta_sum*Gh */
    static wabisabi_knowledge_t kn;

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
    static wabisabi_knowledge_t kn;
    kn.statement = wabisabi_zero_proof_statement(ma);
    kn.witness[0] = *r;
    return kn;
}

/* ---- Range proof ---- */

wabisabi_statement_t
wabisabi_range_proof_statement(const wabisabi_ge_t* ma, const wabisabi_ge_t* bit_commitments, int width) {
    assert(width >= 0 && width <= WABISABI_MAX_RANGE_WIDTH);

    static wabisabi_statement_t stmt;
    memset(&stmt, 0, sizeof(stmt));

    /* rows = 2*width + 1 (or 1 if width==0) */
    stmt.n_equations = width * 2 + 1;
    /* columns = 3*width + 1 (witnesses) */
    stmt.n_witnesses = width * 3 + 1;

    /* Helper indices:
     * witness[0] = r (overall randomness)
     * witness[3*i+1] = b_i (bit value)
     * witness[3*i+2] = r_i (bit randomness)
     * witness[3*i+3] = rb_i = r_i * b_i (product)
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
    stmt.equations[0].n_entries = 0;
    equation_add_entry(&stmt.equations[0], 0, &WABISABI_Gh); /* witness[0] = r */
    for (int i = 0; i < width; i++) {
        equation_add_entry(&stmt.equations[0], RND_COL(i), &WABISABI_NEG_GH_POW2[i]);
    }

    for (int i = 0; i < width; i++) {
        /* Equation BIT_ROW(i): B_i = b_i*Gg + r_i*Gh */
        stmt.equations[BIT_ROW(i)].public_point = bit_commitments[i];
        stmt.equations[BIT_ROW(i)].n_entries = 0;
        equation_add_entry(&stmt.equations[BIT_ROW(i)], BIT_COL(i), &WABISABI_Gg);
        equation_add_entry(&stmt.equations[BIT_ROW(i)], RND_COL(i), &WABISABI_Gh);

        /* Equation BITS_ROW(i): O = b_i*(B_i - Gg) + (-rb_i)*Gh
         * This proves b_i is a bit (b_i = b_i^2) */
        stmt.equations[BITS_ROW(i)].public_point = GE_INFINITY; /* O */
        stmt.equations[BITS_ROW(i)].n_entries = 0;
        wabisabi_ge_t Bi_minus_Gg;
        wabisabi_ge_sub(&Bi_minus_Gg, &bit_commitments[i], &WABISABI_Gg);
        equation_add_entry(&stmt.equations[BITS_ROW(i)], BIT_COL(i), &Bi_minus_Gg);
        wabisabi_ge_t neg_Gh;
        wabisabi_ge_negate(&neg_Gh, &WABISABI_Gh);
        equation_add_entry(&stmt.equations[BITS_ROW(i)], PROD_COL(i), &neg_Gh);
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

    static wabisabi_range_proof_t rp;
    rp.width = width;

    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, amount, randomness);

    /* Derive bit randomness from the random bytes using a simple hash */
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
