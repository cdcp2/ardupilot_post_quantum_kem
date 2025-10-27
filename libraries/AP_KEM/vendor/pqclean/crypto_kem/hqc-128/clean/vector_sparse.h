#ifndef VECTOR_SPARSE_H
#define VECTOR_SPARSE_H

#include "parameters.h"
#include "randombytes.h"
#include <stdint.h>
#include <stddef.h>
#include "shake_prng.h"

int PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight_idx(
    seedexpander_state *ctx, uint16_t *idx, uint16_t weight);

void PQCLEAN_HQC128_CLEAN_vect_add_sparse(
    uint64_t *u, const uint16_t *idx, size_t w);

void PQCLEAN_HQC128_CLEAN_vect_set_from_idx(
    uint64_t *v, const uint16_t *idx, size_t w);

#endif
