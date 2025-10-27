#include "vector_sparse.h"

static uint32_t m_val[PARAM_OMEGA_R] = {
    243079,243093,243106,243120,243134,243148,243161,243175,243189,243203,
    243216,243230,243244,243258,243272,243285,243299,243313,243327,243340,
    243354,243368,243382,243396,243409,243423,243437,243451,243465,243478,
    243492,243506,243520,243534,243547,243561,243575,243589,243603,243616,
    243630,243644,243658,243672,243686,243699,243713,243727,243741,243755,
    243769,243782,243796,243810,243824,243838,243852,243865,243879,243893,
    243907,243921,243935,243949,243962,243976,243990,244004,244018,244032,
    244046,244059,244073,244087,244101
};

/* minimal helpers, time-const where needed */
static inline uint32_t ct_eq_u32(uint32_t a, uint32_t b) {
    return 1 ^ ((uint32_t)((a - b) | (b - a)) >> 31);
}
static uint64_t single_bit_mask(uint32_t pos) {
    uint64_t r = 0, mask = 1, tmp;
    for (size_t i = 0; i < 64; i++) {
        tmp = pos - i;
        tmp = 0 - (1 - ((uint64_t)(tmp | (0 - tmp)) >> 63));
        r |= mask & tmp;
        mask <<= 1;
    }
    return r;
}
static inline uint32_t cond_sub(uint32_t r, uint32_t n) {
    r -= n;
    uint32_t m = 0 - (r >> 31);
    return r + (n & m);
}
static inline uint32_t reduce_u32(uint32_t a, size_t i) {
    uint32_t q = ((uint64_t)a * m_val[i]) >> 32;
    uint32_t n = (uint32_t)(PARAM_N - i);
    uint32_t r = a - q * n;
    return cond_sub(r, n);
}

/* Algorithm 5*/
int PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(
    seedexpander_state *ctx, uint16_t *idx, uint16_t weight) {

    uint8_t  rnd[4 * PARAM_OMEGA_R] = {0};
    uint32_t support[PARAM_OMEGA_R] = {0};
    uint32_t found, mask32;

    if (weight > PARAM_OMEGA_R) return -1;

    PQCLEAN_HQC128_CLEAN_seedexpander(ctx, rnd, 4 * weight);

    for (size_t i = 0; i < weight; i++) {
        uint32_t x = (uint32_t)rnd[4*i]
                   | ((uint32_t)rnd[4*i+1] << 8)
                   | ((uint32_t)rnd[4*i+2] << 16)
                   | ((uint32_t)rnd[4*i+3] << 24);
        support[i] = (uint32_t)(i + reduce_u32(x, i));
    }
    for (size_t i = (size_t)weight - 1; i-- > 0;) {
        found = 0;
        for (size_t j = i + 1; j < weight; j++) found |= ct_eq_u32(support[j], support[i]);
        mask32 = 0 - found;
        support[i] = (mask32 & (uint32_t)i) ^ (~mask32 & support[i]);
    }
    for (size_t i = 0; i < weight; i++) idx[i] = (uint16_t)support[i];
    return 0;
}

/* u ^= e */
void PQCLEAN_HQC128_CLEAN_vect_add_sparse(
    uint64_t *u, const uint16_t *idx, size_t w) {

    for (size_t t = 0; t < w; t++) {
        uint32_t p = idx[t];
        uint32_t w64 = p >> 6;
        uint32_t b   = p & 63u;
        u[w64] ^= single_bit_mask(b);
    }
}

/* v |= e */
void PQCLEAN_HQC128_CLEAN_vect_set_from_idx(
    uint64_t *v, const uint16_t *idx, size_t w) {

    for (size_t t = 0; t < w; t++) {
        uint32_t p = idx[t];
        uint32_t w64 = p >> 6;
        uint32_t b   = p & 63u;
        v[w64] |= single_bit_mask(b);
    }
    if (PARAM_N & 63) {
        v[VEC_N_SIZE_64 - 1] &= ~((~(uint64_t)0) << (PARAM_N & 63));
    }
}
