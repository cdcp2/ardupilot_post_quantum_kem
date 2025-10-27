#include "gf2x_sparse.h"
#include "parameters.h"
#include <stdint.h>
#include <string.h>

static inline void mask_top(uint64_t *a) {
    a[VEC_N_SIZE_64 - 1] &= RED_MASK;
}

static void rotl_extract_window(uint64_t *dst, const uint64_t *src, uint32_t r_bits) {
    size_t n64 = VEC_N_SIZE_64;
    uint64_t twice[(2 * VEC_N_SIZE_64) + 1];
    uint32_t r = (PARAM_N == 0) ? 0u : (r_bits % (uint32_t)PARAM_N);
    uint32_t s = r & 63u;
    uint32_t woff = r >> 6;

    for (size_t i = 0; i < n64; i++) twice[i] = src[i];
    mask_top(twice);
    for (size_t i = 0; i < n64; i++) twice[n64 + i] = twice[i];
    twice[2 * n64] = twice[0];

    if (s == 0) {
        for (size_t i = 0; i < n64; i++) dst[i] = twice[woff + i];
    } else {
        uint32_t sh = 64u - s;
        for (size_t i = 0; i < n64; i++) {
            uint64_t lo = twice[woff + i];
            uint64_t hi = twice[woff + i + 1];
            dst[i] = (lo << s) | (hi >> sh);
        }
    }
    mask_top(dst);
}

void PQCLEAN_HQC128_CLEAN_gf2x_mul_dense_sparse(
    uint64_t *o,
    const uint64_t *u,
    const uint16_t *idx,
    size_t w) {

    uint64_t rot[VEC_N_SIZE_64];

    for (size_t i = 0; i < VEC_N_SIZE_64; i++) o[i] = 0;

    for (size_t t = 0; t < w; t++) {
        uint32_t r = (uint32_t)idx[t];
        rotl_extract_window(rot, u, r);
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) o[i] ^= rot[i];
    }
    mask_top(o);
}
