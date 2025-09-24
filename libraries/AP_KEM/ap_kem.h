#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
// Importa la API del vendor con nombre C para evitar name mangling
#include "vendor/pqclean/crypto_kem/hqc-128/clean/api.h"


// Re-exporta tamaños con tus propios nombres (evita usar PQCLEAN_* fuera):
#define AP_KEM_PUBLICKEYBYTES  PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES
#define AP_KEM_SECRETKEYBYTES  PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES
#define AP_KEM_CIPHERTEXTBYTES PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define AP_KEM_BYTES           PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES


bool ap_kem_keypair(uint8_t *pk, uint8_t *sk);
bool ap_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
bool ap_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#ifdef __cplusplus
}
#endif
