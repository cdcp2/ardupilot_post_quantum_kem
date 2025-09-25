// File: tools/kemtls_pack_hqc128.cpp
// Genera kemtls_pk_default.bin con una PK HQC-128 (PQClean) embebible en ROMFS.
// Compilar y ejecutar en el host (no en el FC).

#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <ctime>

extern "C" {
    #include "ws/ardupilot/libraries/AP_KEM/vendor/pqclean/common/sha2.h"    // fingerprint SHA-256 (PQClean común)
    #include "ws/ardupilot/libraries/AP_KEM/vendor/pqclean/crypto_kem/hqc-128/clean/api.h"   // define CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES
    int PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
}


// --- Header binario kemtls_pk.bin ---
#pragma pack(push,1)
struct kemtls_pk_file_hdr {
    uint32_t magic;         // "KEMT" (0x544D454B LE)
    uint16_t version;       // 1
    uint8_t  suite_id;      // 1=hqc-128
    uint8_t  alg;           // 0 (reservado)
    uint64_t created_unix;  // epoch seconds
    uint32_t pk_len;        // bytes de PK
    uint8_t  pk_fingerprint[32]; // SHA-256(PK)
    uint32_t crc32;         // CRC32(PK)
};
#pragma pack(pop)

// CRC32 sencillo (0xEDB88320)
static uint32_t crc32_buf(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        uint32_t x = (crc ^ data[i]) & 0xFFu;
        for (int b = 0; b < 8; ++b) {
            x = (x >> 1) ^ ((x & 1u) ? 0xEDB88320u : 0u);
        }
        crc = (crc >> 8) ^ x;
    }
    return crc ^ 0xFFFFFFFFu;
}

int main(int argc, char** argv) {
    const char* outpath = (argc > 1) ? argv[1] : "kemtls_pk_default.bin";
    // 1) keypair HQC-128
    std::vector<uint8_t> pk(2249);
    std::vector<uint8_t> sk(2305);
    if (PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk.data(), sk.data()) != 0) {
        std::fprintf(stderr, "keypair failed\n");
        return 1;
    }
    // 2) fingerprint
    uint8_t fp[32];
    sha256(fp, pk.data(), pk.size()); // PQClean SHA-256

    // 3) header
    kemtls_pk_file_hdr hdr{};
    hdr.magic = 0x544D454B; // "KEMT"
    hdr.version = 1;
    hdr.suite_id = 1; // hqc-128
    hdr.alg = 0;
    hdr.created_unix = (uint64_t)std::time(nullptr);
    hdr.pk_len = (uint32_t)pk.size();
    std::memcpy(hdr.pk_fingerprint, fp, 32);
    hdr.crc32 = crc32_buf(pk.data(), pk.size());

    // 4) write file
    std::FILE* f = std::fopen(outpath, "wb");
    if (!f) { std::perror("fopen"); return 2; }
    if (std::fwrite(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { std::fprintf(stderr,"write hdr failed\n"); return 3; }
    if (std::fwrite(pk.data(), 1, pk.size(), f) != pk.size()) { std::fprintf(stderr,"write pk failed\n"); return 4; }
    std::fclose(f);

    std::fprintf(stderr, "Wrote %s (pk=%u bytes)\n", outpath, (unsigned)pk.size());
    // Nota: NO guardamos la SK en firmware. Úsala sólo localmente para pruebas.
    return 0;
}

