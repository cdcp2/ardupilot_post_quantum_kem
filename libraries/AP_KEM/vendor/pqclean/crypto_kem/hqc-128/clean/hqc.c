#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "shake_prng.h"
#include "vector.h"
#include "gf2x_sparse.h"
#include "vector_sparse.h"
#include <stdint.h>
/**
 * @file hqc.c
 * @brief Implementation of hqc.h
 */



/**
 * @brief Keygen of the HQC_PKE IND_CPA scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the <b>seed</b> used to generate the vector <b>h</b>.
 *
 * The secret key is composed of the <b>seed</b> used to generate vectors <b>x</b> and  <b>y</b>.
 * As a technicality, the public key is appended to the secret key in order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 */
void PQCLEAN_HQC128_CLEAN_hqc_pke_keygen(uint8_t *pk, uint8_t *sk) {
    seedexpander_state sk_seedexpander, pk_seedexpander;
    uint8_t sk_seed[SEED_BYTES] = {0};
    uint8_t sigma[VEC_K_SIZE_BYTES] = {0};
    uint8_t pk_seed[SEED_BYTES] = {0};
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};
    uint16_t x_idx[PARAM_OMEGA] = {0};
    uint16_t y_idx[PARAM_OMEGA] = {0};

    randombytes(sk_seed, SEED_BYTES);
    randombytes(sigma, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&sk_seedexpander, sk_seed, SEED_BYTES);

    randombytes(pk_seed, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&pk_seedexpander, pk_seed, SEED_BYTES);

    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(&sk_seedexpander, x_idx, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(&sk_seedexpander, y_idx, PARAM_OMEGA);

    PQCLEAN_HQC128_CLEAN_vect_set_random(&pk_seedexpander, h);
    PQCLEAN_HQC128_CLEAN_gf2x_mul_dense_sparse(s, h, y_idx, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_vect_add_sparse(s, x_idx, PARAM_OMEGA);

    PQCLEAN_HQC128_CLEAN_hqc_public_key_to_string(pk, pk_seed, s);
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_to_string(sk, sk_seed, sigma, pk);

    PQCLEAN_HQC128_CLEAN_seedexpander_release(&pk_seedexpander);
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&sk_seedexpander);
}




/**
 * @brief Encryption of the HQC_PKE IND_CPA scheme
 *
 * The cihertext is composed of vectors <b>u</b> and <b>v</b>.
 *
 * @param[out] u Vector u (first part of the ciphertext)
 * @param[out] v Vector v (second part of the ciphertext)
 * @param[in] m Vector representing the message to encrypt
 * @param[in] theta Seed used to derive randomness required for encryption
 * @param[in] pk String containing the public key
 */
void PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(uint64_t *u, uint64_t *v, uint8_t *m, uint8_t *theta, const uint8_t *pk) {
    seedexpander_state vec_seedexpander;
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};
    uint64_t tmp1[VEC_N_SIZE_64] = {0};
    uint64_t tmp2[VEC_N_SIZE_64] = {0};
    uint16_t r1_idx[PARAM_OMEGA_R] = {0};
    uint16_t r2_idx[PARAM_OMEGA_R] = {0};
    uint16_t e_idx[PARAM_OMEGA_E] = {0};

    PQCLEAN_HQC128_CLEAN_seedexpander_init(&vec_seedexpander, theta, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_hqc_public_key_from_string(h, s, pk);

    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(&vec_seedexpander, r1_idx, PARAM_OMEGA_R);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(&vec_seedexpander, r2_idx, PARAM_OMEGA_R);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(&vec_seedexpander, e_idx, PARAM_OMEGA_E);

    PQCLEAN_HQC128_CLEAN_gf2x_mul_dense_sparse(u, h, r2_idx, PARAM_OMEGA_R);
    PQCLEAN_HQC128_CLEAN_vect_add_sparse(u, r1_idx, PARAM_OMEGA_R);

    PQCLEAN_HQC128_CLEAN_code_encode(v, m);
    PQCLEAN_HQC128_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);

    PQCLEAN_HQC128_CLEAN_gf2x_mul_dense_sparse(tmp2, s, r2_idx, PARAM_OMEGA_R);
    PQCLEAN_HQC128_CLEAN_vect_add_sparse(tmp2, e_idx, PARAM_OMEGA_E);
    PQCLEAN_HQC128_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);

    PQCLEAN_HQC128_CLEAN_seedexpander_release(&vec_seedexpander);
}




/**
 * @brief Decryption of the HQC_PKE IND_CPA scheme
 *
 * @param[out] m Vector representing the decrypted message
 * @param[in] u Vector u (first part of the ciphertext)
 * @param[in] v Vector v (second part of the ciphertext)
 * @param[in] sk String containing the secret key
 * @returns 0
 */
uint8_t PQCLEAN_HQC128_CLEAN_hqc_pke_decrypt(uint8_t *m, uint8_t *sigma, const uint64_t *u, const uint64_t *v, const uint8_t *sk) {
    uint64_t x[VEC_N_SIZE_64] = {0};
    uint64_t y[VEC_N_SIZE_64] = {0};
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    uint64_t tmp1[VEC_N_SIZE_64] = {0};
    uint64_t tmp2[VEC_N_SIZE_64] = {0};
    uint16_t y_idx[PARAM_OMEGA] = {0};
    size_t wc = 0;

    PQCLEAN_HQC128_CLEAN_hqc_secret_key_from_string(x, y, sigma, pk, sk);

    PQCLEAN_HQC128_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);

    for (size_t i = 0; i < VEC_N_SIZE_64 && wc < PARAM_OMEGA; i++) {
        uint64_t w = y[i];
        for (uint32_t b = 0; b < 64 && wc < PARAM_OMEGA; b++) {
            if (w & 1) y_idx[wc++] = (uint16_t)(i * 64 + b);
            w >>= 1;
        }
    }

    PQCLEAN_HQC128_CLEAN_gf2x_mul_dense_sparse(tmp2, u, y_idx, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);

    PQCLEAN_HQC128_CLEAN_code_decode(m, tmp2);
    return 0;
}
