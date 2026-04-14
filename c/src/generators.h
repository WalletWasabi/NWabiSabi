/* Fixed generator points for WabiSabi protocol.
 * Matches WabiSabi/Crypto/Groups/Generators.cs exactly.
 * Each generator is derived by repeated SHA-256 of its name until a valid
 * secp256k1 x-coordinate is found (TryCreateXQuad convention).
 */
#pragma once
#include "wabisabi_types.h"

/* The standard secp256k1 base point */
extern wabisabi_ge_t WABISABI_G;

/* MAC / Show generators */
extern wabisabi_ge_t WABISABI_Gw;
extern wabisabi_ge_t WABISABI_Gwp;
extern wabisabi_ge_t WABISABI_Gx0;
extern wabisabi_ge_t WABISABI_Gx1;
extern wabisabi_ge_t WABISABI_GV;

/* Pedersen commitment generators */
extern wabisabi_ge_t WABISABI_Gg;
extern wabisabi_ge_t WABISABI_Gh;

/* Attribute generator */
extern wabisabi_ge_t WABISABI_Ga;

/* Serial number generator */
extern wabisabi_ge_t WABISABI_Gs;

/* Powers-of-two scalars for range proofs: 2^i for i=0..254 */
extern wabisabi_scalar_t WABISABI_POW2[255];

/* -(2^i) * Gh for range proofs */
extern wabisabi_ge_t WABISABI_NEG_GH_POW2[255];

/* Scalar zero and one */
extern const wabisabi_scalar_t WABISABI_SCALAR_ZERO;
extern const wabisabi_scalar_t WABISABI_SCALAR_ONE;

/* Must be called after wabisabi_init() */
void wabisabi_generators_init(void);

/* Compute a generator from arbitrary bytes (like Generators.FromBuffer).
 * Uses repeated SHA-256 until a valid curve point is found. */
void wabisabi_generator_from_bytes(wabisabi_ge_t* out, const uint8_t* data, size_t len);

/* Same but from a text string */
void wabisabi_generator_from_text(wabisabi_ge_t* out, const char* text);

/* Generate U = hash_to_curve(t) — used in MAC computation */
void wabisabi_generate_u(wabisabi_ge_t* u, const wabisabi_scalar_t* t);
