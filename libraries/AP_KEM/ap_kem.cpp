#include "ap_kem.h"

extern "C" bool ap_kem_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk) == 0;
}
extern "C" bool ap_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk) == 0;
}
extern "C" bool ap_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss, ct, sk) == 0;
}
