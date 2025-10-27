#ifndef GF2X_SPARSE_H
#define GF2X_SPARSE_H

#include <stdint.h>
#include <stddef.h>

void PQCLEAN_HQC128_CLEAN_gf2x_mul_dense_sparse(
    uint64_t *o,
    const uint64_t *u,
    const uint16_t *idx,
    size_t w);

#endif
