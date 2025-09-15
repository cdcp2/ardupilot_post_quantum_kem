#pragma once
#ifndef AP_CRYPTO_AEAD_IFACE_H
#define AP_CRYPTO_AEAD_IFACE_H

#include <cstddef>
#include <cstdint>

// Evita choques de tipos globales; constantes en lugar de enum class
constexpr uint8_t AP_AEAD_ALG_NONE     = 0;
constexpr uint8_t AP_AEAD_ALG_ASCON128 = 1;

struct AP_AEAD_Sizes { size_t key, npub, tag; };

class AP_CryptoAEAD {
public:
    virtual ~AP_CryptoAEAD() = default;

    virtual bool sizes(AP_AEAD_Sizes& out) const = 0;

    virtual bool encrypt(uint8_t* c, size_t& clen,
                         const uint8_t* m, size_t mlen,
                         const uint8_t* ad, size_t adlen,
                         const uint8_t* npub,
                         const uint8_t* key) = 0;

    virtual bool decrypt(uint8_t* m, size_t& mlen,
                         const uint8_t* c, size_t clen,
                         const uint8_t* ad, size_t adlen,
                         const uint8_t* npub,
                         const uint8_t* key) = 0;
};

// Fábrica (declaración)
AP_CryptoAEAD* AP_Crypto_GetAEAD_Ascon();

#endif // AP_CRYPTO_AEAD_IFACE_H
