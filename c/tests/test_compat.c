/*
 * tests/test_compat.c
 *
 * C# test suite migrated to C. Each section references the originating file:
 *
 *   GroupElements/GeneratorTests.cs  → test_generators_hex()
 *   GroupElements/GeneralTests.cs    → test_from_text()
 *   GroupElements/OperationTests.cs  → test_group_operations()
 *   MacTests.cs                      → test_mac()
 *   ProofSystemTests.cs (MAC proof)  → test_proof_issuer_params()
 *   KnowledgeOfDlogTests.cs          → test_knowledge_of_dlog()
 *   KnowledgeOfRepTests.cs           → test_knowledge_of_rep()
 *   ProofSystemTests.cs (balance)    → test_balance_proof()
 *   ProofSystemTests.cs (range)      → test_range_proof()
 *   ProofSystemTests.cs (zero)       → test_zero_proofs()
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generators.h"
#include "mac.h"
#include "proof.h"
#include "transcript.h"
#include "wabisabi_types.h"

/* ------------------------------------------------------------------ */
/* Minimal test framework                                               */
/* ------------------------------------------------------------------ */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, expr)                                                                                             \
    do {                                                                                                               \
        if (expr) {                                                                                                    \
            g_pass++;                                                                                                  \
        } else {                                                                                                       \
            fprintf(stderr, "  FAIL [line %d]: %s\n", __LINE__, (label));                                              \
            g_fail++;                                                                                                  \
        }                                                                                                              \
    } while (0)

/* ------------------------------------------------------------------ */
/* Utilities                                                            */
/* ------------------------------------------------------------------ */

static int
hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int
bytes_match_hex(const uint8_t* b, size_t len, const char* hex) {
    if (strlen(hex) != len * 2) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0 || b[i] != (uint8_t)((hi << 4) | lo)) {
            return 0;
        }
    }
    return 1;
}

static int
ge_matches_hex(const wabisabi_ge_t* ge, const char* hex) {
    uint8_t buf[33];
    wabisabi_ge_serialize(buf, ge);
    return bytes_match_hex(buf, 33, hex);
}

/* Scalar from a 32-bit value; big-endian placement at bytes [28..31] */
static wabisabi_scalar_t
scalar_from_u32(uint32_t v) {
    wabisabi_scalar_t s = WABISABI_SCALAR_ZERO;
    s.data[28] = (uint8_t)(v >> 24);
    s.data[29] = (uint8_t)(v >> 16);
    s.data[30] = (uint8_t)(v >> 8);
    s.data[31] = (uint8_t)v;
    return s;
}

/* P = secret * generator (1 equation, 1 witness) */
static wabisabi_knowledge_t
make_dlog_knowledge(const wabisabi_scalar_t* secret, const wabisabi_ge_t* gen) {
    wabisabi_knowledge_t kn;
    memset(&kn.statement, 0, sizeof(kn.statement));
    kn.statement.n_equations = 1;
    kn.statement.n_witnesses = 1;
    wabisabi_ge_mul(&kn.statement.equations[0].public_point, secret, gen);
    kn.statement.equations[0].generators[0] = *gen;
    kn.statement.equations[0].n_gen = 1;
    kn.witness[0] = *secret;
    return kn;
}

/* P = s1*g1 + s2*g2 (1 equation, 2 witnesses) */
static wabisabi_knowledge_t
make_rep_knowledge(const wabisabi_scalar_t* s1, const wabisabi_scalar_t* s2, const wabisabi_ge_t* g1,
                   const wabisabi_ge_t* g2) {
    wabisabi_knowledge_t kn;
    memset(&kn.statement, 0, sizeof(kn.statement));
    kn.statement.n_equations = 1;
    kn.statement.n_witnesses = 2;

    wabisabi_ge_t t1, t2;
    wabisabi_ge_mul(&t1, s1, g1);
    wabisabi_ge_mul(&t2, s2, g2);
    wabisabi_ge_add(&kn.statement.equations[0].public_point, &t1, &t2);
    kn.statement.equations[0].generators[0] = *g1;
    kn.statement.equations[0].generators[1] = *g2;
    kn.statement.equations[0].n_gen = 2;

    kn.witness[0] = *s1;
    kn.witness[1] = *s2;
    return kn;
}

/* Run prove + verify under a fresh transcript pair. Returns 1 if valid. */
static int
prove_and_verify(const uint8_t* label, size_t label_len, const wabisabi_knowledge_t* kns, int n, const uint8_t* rnd,
                 size_t rnd_len) {
    wabisabi_transcript_t t1, t2;
    wabisabi_transcript_init(&t1, label, label_len);
    wabisabi_transcript_clone(&t2, &t1);

    wabisabi_proof_t* proofs = malloc((size_t)n * sizeof(wabisabi_proof_t));
    wabisabi_statement_t* stmts = malloc((size_t)n * sizeof(wabisabi_statement_t));
    if (!proofs || !stmts) {
        free(proofs);
        free(stmts);
        return 0;
    }

    wabisabi_prove(proofs, &t1, kns, n, rnd, rnd_len);
    for (int i = 0; i < n; i++) {
        stmts[i] = kns[i].statement;
    }
    int ok = wabisabi_verify(&t2, stmts, n, proofs, n);

    free(proofs);
    free(stmts);
    return ok;
}

static const uint8_t LABEL[] = "WabiSabiCompatTest";
static const uint8_t ZERO_RND[32] = {0};

/* ================================================================== */
/* 1. GeneratorTests.cs — GeneratorsArentChanged                       */
/* ================================================================== */

static void
test_generators_hex(void) {
    printf("  [GeneratorTests - GeneratorsArentChanged]\n");

    CHECK("G", ge_matches_hex(&WABISABI_G, "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
    CHECK("Ga", ge_matches_hex(&WABISABI_Ga, "03AB8F46084B4FA0FC8261328A5A71AF267B1D1F8FE229C63C751D02A2E996E0EC"));
    CHECK("Gg", ge_matches_hex(&WABISABI_Gg, "02FB8868ACD9CBBD68964BAA1CFA6B893A6269E01569183474E6C1C4242A0071A9"));
    CHECK("Gh", ge_matches_hex(&WABISABI_Gh, "023D11E10CE7A8C17671ED777886FC2B84E65A532FA0C411ABBE96E1206F9DFF80"));
    CHECK("Gs", ge_matches_hex(&WABISABI_Gs, "031E7775ED62B79E9E83366198CFE69DFE7408AFF10C331CEE3B2C7F7A5F2EB0C8"));
    CHECK("GV", ge_matches_hex(&WABISABI_GV, "03665E9B8468DCEDA16ED3E315FBD0A0E597F4AA3B4C6F2146437F53F3AF204C2C"));
    CHECK("Gw", ge_matches_hex(&WABISABI_Gw, "02B4DF49B623A8A0B245CCF2867134A5DAC12FE39ECEC08B3D361801D2C79DDC14"));
    CHECK("Gwp", ge_matches_hex(&WABISABI_Gwp, "03F50265578FCE5E977162E662ED75D7224AE720FA79B72CF2B6FB86B2136E3B48"));
    CHECK("Gx0", ge_matches_hex(&WABISABI_Gx0, "02E33C9F3CBE6388A2D3C3ECB12153DB73499928541905D86AAA4FFC01F2763B54"));
    CHECK("Gx1", ge_matches_hex(&WABISABI_Gx1, "0246253CC926AAB789BAA278AB9A54EDEF455CA2014038E9F84DE312C05A8121CC"));

    /* All generators must be distinct points */
    CHECK("G != Gw", !wabisabi_ge_equal(&WABISABI_G, &WABISABI_Gw));
    CHECK("Gg != Gh", !wabisabi_ge_equal(&WABISABI_Gg, &WABISABI_Gh));
    CHECK("Gw != Gwp", !wabisabi_ge_equal(&WABISABI_Gw, &WABISABI_Gwp));
    CHECK("Gx0 != Gx1", !wabisabi_ge_equal(&WABISABI_Gx0, &WABISABI_Gx1));

    /* No generator is the point at infinity */
    CHECK("G not inf", !WABISABI_G.is_infinity);
    CHECK("Ga not inf", !WABISABI_Ga.is_infinity);
    CHECK("Gg not inf", !WABISABI_Gg.is_infinity);
    CHECK("Gh not inf", !WABISABI_Gh.is_infinity);
    CHECK("GV not inf", !WABISABI_GV.is_infinity);
    CHECK("Gw not inf", !WABISABI_Gw.is_infinity);
    CHECK("Gwp not inf", !WABISABI_Gwp.is_infinity);
    CHECK("Gx0 not inf", !WABISABI_Gx0.is_infinity);
    CHECK("Gx1 not inf", !WABISABI_Gx1.is_infinity);
    CHECK("Gs not inf", !WABISABI_Gs.is_infinity);
}

/* ================================================================== */
/* 2. GeneralTests.cs — FromText                                       */
/* ================================================================== */

static void
test_from_text(void) {
    printf("  [GeneralTests - FromText]\n");

    static const struct {
        const char* input;
        const char* hex;
    } cases[] = {
        {"", "02E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
        {" ", "0224944F33566D9ED9C410AE72F89454AC6F0CFEE446590C01751F094E185E8978"},
        {"  ", "026C179F21E6F62B629055D8AB40F454ED02E48B68563913473B857D3638E23B28"},
        {"a", "02EB48BDFA15FC43DBEA3AABB1EE847B6E69232C0F0D9705935E50D60CCE77877F"},
        {"12345", "035994471ABB01112AFCC18159F6CC74B4F511B99806DA59B3CAF5A9C173CACFC5"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wabisabi_ge_t ge;
        wabisabi_generator_from_text(&ge, cases[i].input);
        char label[64];
        snprintf(label, sizeof(label), "FromText(\"%s\")", cases[i].input);
        CHECK(label, ge_matches_hex(&ge, cases[i].hex));
    }

    /* FromText is deterministic — same input gives same result */
    {
        wabisabi_ge_t a, b;
        wabisabi_generator_from_text(&a, "hello");
        wabisabi_generator_from_text(&b, "hello");
        CHECK("FromText deterministic", wabisabi_ge_equal(&a, &b));
    }

    /* Different inputs give different results */
    {
        wabisabi_ge_t a, b;
        wabisabi_generator_from_text(&a, "hello");
        wabisabi_generator_from_text(&b, "world");
        CHECK("FromText injective", !wabisabi_ge_equal(&a, &b));
    }
}

/* ================================================================== */
/* 3. OperationTests.cs — addition, subtraction, negation, multiply   */
/* ================================================================== */

static void
test_group_operations(void) {
    printf("  [OperationTests - group element arithmetic]\n");

    wabisabi_ge_t inf;
    inf.is_infinity = 1;
    memset(&inf.pk, 0, sizeof(inf.pk));

    wabisabi_scalar_t s1 = scalar_from_u32(1);
    wabisabi_scalar_t s2 = scalar_from_u32(2);
    wabisabi_scalar_t s3 = scalar_from_u32(3);

    wabisabi_ge_t G1, G2, G3;
    wabisabi_ge_mul(&G1, &s1, &WABISABI_G);
    wabisabi_ge_mul(&G2, &s2, &WABISABI_G);
    wabisabi_ge_mul(&G3, &s3, &WABISABI_G);

    wabisabi_ge_t r;

    /* Addition */
    wabisabi_ge_add(&r, &inf, &WABISABI_G);
    CHECK("inf + G = G", wabisabi_ge_equal(&r, &WABISABI_G));

    wabisabi_ge_add(&r, &WABISABI_G, &inf);
    CHECK("G + inf = G", wabisabi_ge_equal(&r, &WABISABI_G));

    wabisabi_ge_add(&r, &inf, &inf);
    CHECK("inf + inf = inf", r.is_infinity);

    wabisabi_ge_add(&r, &G1, &G1);
    CHECK("1*G + 1*G = 2*G", wabisabi_ge_equal(&r, &G2));

    wabisabi_ge_add(&r, &G1, &G2);
    CHECK("1*G + 2*G = 3*G", wabisabi_ge_equal(&r, &G3));

    wabisabi_ge_add(&r, &G2, &G1);
    CHECK("addition is commutative", wabisabi_ge_equal(&r, &G3));

    /* Subtraction */
    wabisabi_ge_t neg_G;
    wabisabi_ge_negate(&neg_G, &WABISABI_G);

    wabisabi_ge_sub(&r, &inf, &WABISABI_G);
    CHECK("inf - G = -G", wabisabi_ge_equal(&r, &neg_G));

    wabisabi_ge_sub(&r, &WABISABI_G, &inf);
    CHECK("G - inf = G", wabisabi_ge_equal(&r, &WABISABI_G));

    wabisabi_ge_sub(&r, &inf, &inf);
    CHECK("inf - inf = inf", r.is_infinity);

    wabisabi_ge_sub(&r, &G1, &G1);
    CHECK("G - G = inf", r.is_infinity);

    wabisabi_ge_sub(&r, &G2, &G1);
    CHECK("2*G - 1*G = 1*G", wabisabi_ge_equal(&r, &G1));

    wabisabi_ge_sub(&r, &G1, &G2);
    CHECK("1*G - 2*G = -G", wabisabi_ge_equal(&r, &neg_G));

    /* Negation */
    wabisabi_ge_negate(&r, &inf);
    CHECK("negate(inf) = inf", r.is_infinity);

    wabisabi_ge_negate(&r, &neg_G);
    CHECK("negate(-G) = G", wabisabi_ge_equal(&r, &WABISABI_G));

    wabisabi_ge_add(&r, &WABISABI_G, &neg_G);
    CHECK("G + (-G) = inf", r.is_infinity);

    /* Scalar multiplication */
    wabisabi_ge_mul_base(&r, &WABISABI_SCALAR_ONE);
    CHECK("1*G (base) = G", wabisabi_ge_equal(&r, &WABISABI_G));

    wabisabi_ge_mul(&r, &WABISABI_SCALAR_ONE, &WABISABI_G);
    CHECK("1*G = G", wabisabi_ge_equal(&r, &WABISABI_G));

    wabisabi_ge_mul(&r, &WABISABI_SCALAR_ZERO, &WABISABI_G);
    CHECK("0*G = inf", r.is_infinity);

    wabisabi_ge_mul(&r, &s1, &inf);
    CHECK("1 * inf = inf", r.is_infinity);

    wabisabi_ge_mul(&r, &s2, &inf);
    CHECK("2 * inf = inf", r.is_infinity);

    /* Scalar multiply distributes over addition */
    wabisabi_ge_t s3_G, s1_G_plus_s2_G;
    wabisabi_ge_mul(&s3_G, &s3, &WABISABI_G);
    wabisabi_ge_add(&s1_G_plus_s2_G, &G1, &G2);
    CHECK("(1+2)*G = 1*G + 2*G", wabisabi_ge_equal(&s3_G, &s1_G_plus_s2_G));

    /* Serialisation round-trip */
    uint8_t buf[33];
    wabisabi_ge_serialize(buf, &WABISABI_G);
    wabisabi_ge_t G_rt;
    int parsed = wabisabi_ge_parse(&G_rt, buf);
    CHECK("G serialise/deserialise parsed", parsed);
    CHECK("G serialise/deserialise equal", wabisabi_ge_equal(&G_rt, &WABISABI_G));

    /* Infinity serialises to 33 zero bytes */
    wabisabi_ge_serialize(buf, &inf);
    int all_zero = 1;
    for (int i = 0; i < 33; i++) {
        if (buf[i]) {
            all_zero = 0;
            break;
        }
    }
    CHECK("infinity serialises to all-zero", all_zero);

    /* Infinity deserialises from leading-zero byte */
    uint8_t inf_bytes[33] = {0};
    wabisabi_ge_t inf2;
    wabisabi_ge_parse(&inf2, inf_bytes);
    CHECK("all-zero 33 bytes deserialises to infinity", inf2.is_infinity);

    /* EvenOddSerialization: G has even y (prefix 0x02) */
    wabisabi_ge_serialize(buf, &WABISABI_G);
    CHECK("G has even-y prefix (0x02)", buf[0] == 0x02);

    wabisabi_ge_serialize(buf, &neg_G);
    CHECK("-G has odd-y prefix (0x03)", buf[0] == 0x03);
}

/* ================================================================== */
/* 4. MacTests.cs                                                       */
/* ================================================================== */

static void
test_mac(void) {
    printf("  [MacTests - compute, verify, invalid detection]\n");

    wabisabi_sk_t sk;
    sk.w = scalar_from_u32(1);
    sk.wp = scalar_from_u32(2);
    sk.x0 = scalar_from_u32(3);
    sk.x1 = scalar_from_u32(4);
    sk.ya = scalar_from_u32(5);

    wabisabi_scalar_t amount = scalar_from_u32(100);
    wabisabi_scalar_t r = scalar_from_u32(7);
    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, &amount, &r);

    wabisabi_scalar_t t = scalar_from_u32(42);
    wabisabi_mac_t mac;
    wabisabi_mac_compute(&mac, &sk, &ma, &t);

    CHECK("V is not infinity", !mac.v.is_infinity);
    CHECK("t is stored verbatim", memcmp(mac.t.data, t.data, 32) == 0);

    /* CanDetectInvalidMAC — different t gives different V */
    wabisabi_scalar_t t2 = scalar_from_u32(43);
    wabisabi_mac_t mac2;
    wabisabi_mac_compute(&mac2, &sk, &ma, &t2);
    CHECK("different t → different V", !wabisabi_ge_equal(&mac.v, &mac2.v));

    /* Different attribute gives different V */
    wabisabi_scalar_t amount2 = scalar_from_u32(200);
    wabisabi_ge_t ma2;
    wabisabi_pedersen_commit(&ma2, &amount2, &r);
    wabisabi_mac_t mac3;
    wabisabi_mac_compute(&mac3, &sk, &ma2, &t);
    CHECK("different attribute → different V", !wabisabi_ge_equal(&mac.v, &mac3.v));

    /* Different SK gives different V */
    wabisabi_sk_t sk2 = sk;
    sk2.w = scalar_from_u32(99);
    wabisabi_mac_t mac4;
    wabisabi_mac_compute(&mac4, &sk2, &ma, &t);
    CHECK("different SK → different V", !wabisabi_ge_equal(&mac.v, &mac4.v));

    /* EqualityTests — same inputs must give equal MAC */
    wabisabi_mac_t mac5;
    wabisabi_mac_compute(&mac5, &sk, &ma, &t);
    CHECK("same inputs → same V", wabisabi_ge_equal(&mac.v, &mac5.v));
    CHECK("same inputs → same t", memcmp(mac.t.data, mac5.t.data, 32) == 0);

    /* U = hash_to_curve(t) is reproducible */
    wabisabi_ge_t U1, U2;
    wabisabi_mac_get_u(&U1, &mac);
    wabisabi_mac_get_u(&U2, &mac);
    CHECK("U is reproducible", wabisabi_ge_equal(&U1, &U2));
    CHECK("U is not infinity", !U1.is_infinity);
}

/* ================================================================== */
/* 5. ProofSystemTests.cs — CanProveAndVerifyMAC                       */
/* ================================================================== */

static void
test_proof_issuer_params(void) {
    printf("  [ProofSystemTests - CanProveAndVerifyMAC]\n");

    wabisabi_sk_t sk;
    sk.w = scalar_from_u32(11);
    sk.wp = scalar_from_u32(22);
    sk.x0 = scalar_from_u32(33);
    sk.x1 = scalar_from_u32(44);
    sk.ya = scalar_from_u32(55);

    wabisabi_scalar_t amount = scalar_from_u32(10000);
    wabisabi_scalar_t r = scalar_from_u32(77);
    wabisabi_ge_t ma;
    wabisabi_pedersen_commit(&ma, &amount, &r);

    wabisabi_scalar_t t = scalar_from_u32(13);
    wabisabi_mac_t mac;
    wabisabi_mac_compute(&mac, &sk, &ma, &t);

    wabisabi_knowledge_t kn;
    wabisabi_issuer_params_knowledge(&kn, &mac, &ma, &sk);

    CHECK("issuer params proof verifies", prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));

    /* Corrupt the public point in equation 0 — must fail */
    wabisabi_knowledge_t kn_bad = kn;
    wabisabi_ge_add(&kn_bad.statement.equations[0].public_point, &kn_bad.statement.equations[0].public_point,
                    &WABISABI_G); /* shift by G */
    CHECK("corrupted public point fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn_bad, 1, ZERO_RND, 32));

    /* Wrong witness fails */
    wabisabi_knowledge_t kn_w = kn;
    kn_w.witness[0] = scalar_from_u32(999);
    CHECK("wrong witness fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn_w, 1, ZERO_RND, 32));
}

/* ================================================================== */
/* 6. KnowledgeOfDlogTests.cs — End2EndVerificationSimple             */
/* ================================================================== */

static void
test_knowledge_of_dlog(void) {
    printf("  [KnowledgeOfDlogTests - End2EndVerificationSimple]\n");

    /* Seeds from C# [InlineData(1, 3, 5, 7, short.MaxValue, int.MaxValue, uint.MaxValue)] */
    static const uint32_t seeds[] = {1, 3, 5, 7, 32767, 2147483647U, 4294967295U};

    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++) {
        wabisabi_scalar_t s = scalar_from_u32(seeds[i]);

        /* Dlog with secp256k1 base point G */
        wabisabi_knowledge_t kn = make_dlog_knowledge(&s, &WABISABI_G);
        char lbl[48];
        snprintf(lbl, sizeof(lbl), "dlog(G) seed=%u", seeds[i]);
        CHECK(lbl, prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));

        /* Also with generator Ga (like C# tests with 4*G as custom generator) */
        wabisabi_knowledge_t kn2 = make_dlog_knowledge(&s, &WABISABI_Ga);
        snprintf(lbl, sizeof(lbl), "dlog(Ga) seed=%u", seeds[i]);
        CHECK(lbl, prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn2, 1, ZERO_RND, 32));
    }

    /* Wrong witness must not verify */
    {
        wabisabi_scalar_t s = scalar_from_u32(7);
        wabisabi_knowledge_t kn = make_dlog_knowledge(&s, &WABISABI_G);
        kn.witness[0] = scalar_from_u32(8); /* tamper */
        CHECK("dlog wrong witness fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }

    /* Proof is transcript-bound: different label → different challenge */
    {
        wabisabi_scalar_t s = scalar_from_u32(5);
        wabisabi_knowledge_t kn = make_dlog_knowledge(&s, &WABISABI_G);

        /* prove under "LabelA", verify under "LabelB" */
        const uint8_t la[] = "LabelA", lb[] = "LabelB";
        wabisabi_transcript_t t1, t2;
        wabisabi_transcript_init(&t1, la, sizeof(la) - 1);
        wabisabi_transcript_init(&t2, lb, sizeof(lb) - 1);

        wabisabi_proof_t proof;
        wabisabi_statement_t stmt = kn.statement;
        wabisabi_prove(&proof, &t1, &kn, 1, ZERO_RND, 32);
        CHECK("cross-label proof fails", !wabisabi_verify(&t2, &stmt, 1, &proof, 1));
    }
}

/* ================================================================== */
/* 7. KnowledgeOfRepTests.cs — End2EndVerificationSimple              */
/* ================================================================== */

static void
test_knowledge_of_rep(void) {
    printf("  [KnowledgeOfRepTests - End2EndVerificationSimple]\n");

    /* Seed pairs from C# InlineData */
    static const struct {
        uint32_t a, b;
    } pairs[] = {{1, 1},
                 {1, 2},
                 {3, 5},
                 {5, 7},
                 {7, 11},
                 {32767, 4294967295U},
                 {2147483647U, 4294967295U},
                 {4294967295U, 4294967295U}};

    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        wabisabi_scalar_t s1 = scalar_from_u32(pairs[i].a);
        wabisabi_scalar_t s2 = scalar_from_u32(pairs[i].b);
        wabisabi_knowledge_t kn = make_rep_knowledge(&s1, &s2, &WABISABI_G, &WABISABI_Ga);

        char lbl[64];
        snprintf(lbl, sizeof(lbl), "rep(%u,%u)", pairs[i].a, pairs[i].b);
        CHECK(lbl, prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }

    /* Wrong s1 must not verify */
    {
        wabisabi_scalar_t s1 = scalar_from_u32(3), s2 = scalar_from_u32(5);
        wabisabi_knowledge_t kn = make_rep_knowledge(&s1, &s2, &WABISABI_G, &WABISABI_Ga);
        kn.witness[0] = scalar_from_u32(4); /* tamper */
        CHECK("rep wrong s1 fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }

    /* Wrong s2 must not verify */
    {
        wabisabi_scalar_t s1 = scalar_from_u32(3), s2 = scalar_from_u32(5);
        wabisabi_knowledge_t kn = make_rep_knowledge(&s1, &s2, &WABISABI_G, &WABISABI_Ga);
        kn.witness[1] = scalar_from_u32(6); /* tamper */
        CHECK("rep wrong s2 fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }

    /* Chaum-Pedersen: same secret for two generators (x*G, x*Ga) — 2 equations, 1 witness */
    {
        wabisabi_scalar_t x = scalar_from_u32(42);
        wabisabi_knowledge_t kn;
        memset(&kn.statement, 0, sizeof(kn.statement));
        kn.statement.n_equations = 2;
        kn.statement.n_witnesses = 1;

        /* eq0: x*G  */
        wabisabi_ge_mul(&kn.statement.equations[0].public_point, &x, &WABISABI_G);
        kn.statement.equations[0].generators[0] = WABISABI_G;
        kn.statement.equations[0].n_gen = 1;

        /* eq1: x*Ga */
        wabisabi_ge_mul(&kn.statement.equations[1].public_point, &x, &WABISABI_Ga);
        kn.statement.equations[1].generators[0] = WABISABI_Ga;
        kn.statement.equations[1].n_gen = 1;

        kn.witness[0] = x;
        CHECK("Chaum-Pedersen dlog equality", prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }
}

/* ================================================================== */
/* 8. ProofSystemTests.cs — CanProveAndVerifyPresentedBalance          */
/* ================================================================== */

static void
test_balance_proof(void) {
    printf("  [ProofSystemTests - CanProveAndVerifyBalance]\n");

    /* Verify that balance_proof_knowledge(z, r_delta) is internally consistent
     * for a range of (z, r_delta) pairs, mirroring the C# parametrised test. */
    static const struct {
        uint32_t z;
        uint32_t rd;
    } cases[] = {{0, 0},
                 {0, 1},
                 {1, 0},
                 {1, 1},
                 {7, 11},
                 {11, 7},
                 {10000, 0},
                 {0, 10000},
                 {10000, 10000},
                 {2147483646U, 2147483647U},
                 {2147483647U, 2147483646U}};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wabisabi_scalar_t z = scalar_from_u32(cases[i].z);
        wabisabi_scalar_t rd = scalar_from_u32(cases[i].rd);

        wabisabi_knowledge_t kn = wabisabi_balance_proof_knowledge(&z, &rd);
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "balance(z=%u,rd=%u)", cases[i].z, cases[i].rd);
        CHECK(lbl, prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }

    /* Tampered z witness fails */
    {
        wabisabi_scalar_t z = scalar_from_u32(5);
        wabisabi_scalar_t rd = scalar_from_u32(3);
        wabisabi_knowledge_t kn = wabisabi_balance_proof_knowledge(&z, &rd);
        kn.witness[0] = scalar_from_u32(6);
        CHECK("balance wrong z fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }

    /* Tampered r_delta witness fails */
    {
        wabisabi_scalar_t z = scalar_from_u32(5);
        wabisabi_scalar_t rd = scalar_from_u32(3);
        wabisabi_knowledge_t kn = wabisabi_balance_proof_knowledge(&z, &rd);
        kn.witness[1] = scalar_from_u32(4);
        CHECK("balance wrong r_delta fails", !prove_and_verify(LABEL, sizeof(LABEL) - 1, &kn, 1, ZERO_RND, 32));
    }
}

/* ================================================================== */
/* 9. ProofSystemTests.cs — CanProveAndVerifyCommitmentRange           */
/* ================================================================== */

static void
test_range_proof(void) {
    printf("  [ProofSystemTests - CanProveAndVerifyCommitmentRange]\n");

    /* (amount, width, should_verify) — exact InlineData from C# */
    static const struct {
        uint32_t amount;
        int width;
        int pass;
    } cases[] = {
        {0, 0, 1}, {0, 1, 1}, {1, 0, 0}, {1, 1, 1}, {1, 2, 1}, {2, 0, 0}, {2, 1, 0},
        {2, 2, 1}, {3, 1, 0}, {3, 2, 1}, {4, 2, 0}, {4, 3, 1}, {7, 2, 0}, {7, 3, 1},
    };

    /* Fixed randomness and bit-randomness seed */
    wabisabi_scalar_t randomness = scalar_from_u32(12345);
    static const uint8_t rnd[32] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03,
                                    0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                                    0x70, 0x80, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wabisabi_scalar_t a = scalar_from_u32(cases[i].amount);
        int width = cases[i].width;

        wabisabi_ge_t ma;
        wabisabi_pedersen_commit(&ma, &a, &randomness);

        wabisabi_range_proof_t rp = wabisabi_range_proof_knowledge(&a, &randomness, width, rnd, 32);

        wabisabi_statement_t stmt = wabisabi_range_proof_statement(&ma, rp.bit_commitments, width);

        wabisabi_transcript_t t1, t2;
        wabisabi_transcript_init(&t1, LABEL, sizeof(LABEL) - 1);
        wabisabi_transcript_clone(&t2, &t1);

        wabisabi_proof_t proof;
        wabisabi_prove(&proof, &t1, &rp.knowledge, 1, rnd, 32);
        int ok = wabisabi_verify(&t2, &stmt, 1, &proof, 1);

        char lbl[64];
        snprintf(lbl, sizeof(lbl), "range(amount=%u, width=%d) → %s", cases[i].amount, width,
                 cases[i].pass ? "pass" : "fail");
        CHECK(lbl, ok == cases[i].pass);
    }
}

/* ================================================================== */
/* 10. ProofSystemTests.cs — CanProveAndVerifyZeroProofs               */
/* ================================================================== */

static void
test_zero_proofs(void) {
    printf("  [ProofSystemTests - CanProveAndVerifyZeroProofs]\n");

    /* Two zero-value credentials proved jointly under one transcript */
    wabisabi_scalar_t r0 = scalar_from_u32(111);
    wabisabi_scalar_t r1 = scalar_from_u32(222);

    wabisabi_ge_t ma0, ma1;
    /* Zero amount: 0*Gg + r*Gh.  0*Gg = infinity, so ma = r*Gh. */
    wabisabi_ge_mul(&ma0, &r0, &WABISABI_Gh);
    wabisabi_ge_mul(&ma1, &r1, &WABISABI_Gh);

    wabisabi_knowledge_t kn[2];
    kn[0] = wabisabi_zero_proof_knowledge(&ma0, &r0);
    kn[1] = wabisabi_zero_proof_knowledge(&ma1, &r1);

    wabisabi_statement_t stmts[2];
    stmts[0] = wabisabi_zero_proof_statement(&ma0);
    stmts[1] = wabisabi_zero_proof_statement(&ma1);

    wabisabi_transcript_t t1, t2;
    wabisabi_transcript_init(&t1, LABEL, sizeof(LABEL) - 1);
    wabisabi_transcript_clone(&t2, &t1);

    wabisabi_proof_t proofs[2];
    wabisabi_prove(proofs, &t1, kn, 2, ZERO_RND, 32);
    CHECK("two zero proofs verify", wabisabi_verify(&t2, stmts, 2, proofs, 2));

    /* A non-zero amount (1*Gg + r*Gh) must fail as a zero proof */
    wabisabi_scalar_t one_amount = scalar_from_u32(1);
    wabisabi_ge_t ma_nonzero;
    wabisabi_pedersen_commit(&ma_nonzero, &one_amount, &r0);

    wabisabi_knowledge_t kn_bad = wabisabi_zero_proof_knowledge(&ma_nonzero, &r0);
    wabisabi_statement_t stmt_bad = wabisabi_zero_proof_statement(&ma_nonzero);

    wabisabi_transcript_init(&t1, LABEL, sizeof(LABEL) - 1);
    wabisabi_transcript_clone(&t2, &t1);

    wabisabi_proof_t proof_bad;
    wabisabi_prove(&proof_bad, &t1, &kn_bad, 1, ZERO_RND, 32);
    CHECK("non-zero amount fails zero proof", !wabisabi_verify(&t2, &stmt_bad, 1, &proof_bad, 1));

    /* Proofs are NOT interchangeable between different ma values */
    {
        wabisabi_scalar_t r2 = scalar_from_u32(333);
        wabisabi_ge_t ma2;
        wabisabi_ge_mul(&ma2, &r2, &WABISABI_Gh);

        wabisabi_knowledge_t kn2 = wabisabi_zero_proof_knowledge(&ma0, &r0);
        wabisabi_statement_t stmt2 = wabisabi_zero_proof_statement(&ma2); /* different ma */

        wabisabi_transcript_init(&t1, LABEL, sizeof(LABEL) - 1);
        wabisabi_transcript_clone(&t2, &t1);

        wabisabi_proof_t proof2;
        wabisabi_prove(&proof2, &t1, &kn2, 1, ZERO_RND, 32);
        CHECK("proof for ma0 fails against ma2 statement", !wabisabi_verify(&t2, &stmt2, 1, &proof2, 1));
    }
}

/* ================================================================== */
/* Entry point                                                          */
/* ================================================================== */

int
run_compat_tests(void) {
    int pass_before = g_pass;
    int fail_before = g_fail;

    test_generators_hex();
    test_from_text();
    test_group_operations();
    test_mac();
    test_proof_issuer_params();
    test_knowledge_of_dlog();
    test_knowledge_of_rep();
    test_balance_proof();
    test_range_proof();
    test_zero_proofs();

    int new_pass = g_pass - pass_before;
    int new_fail = g_fail - fail_before;
    printf("\nC# compat tests: %d passed, %d failed\n", new_pass, new_fail);
    return new_fail;
}
