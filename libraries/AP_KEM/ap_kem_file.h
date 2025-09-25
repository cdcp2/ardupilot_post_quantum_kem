#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct kemtls_pk_file_hdr {
    uint32_t magic;        
    uint16_t version;       
    uint8_t  suite_id;      
    uint8_t  alg;           
    uint64_t created_unix; 
    uint32_t pk_len;        
    uint8_t  pk_fingerprint[32]; 
    uint32_t crc32;         
} __attribute__((packed));


bool save_kemtls_pk_atomic(const std::string& path,
                           const uint8_t* pk, size_t pk_len,
                           uint8_t suite_id, uint8_t alg,
                           uint64_t created_unix,
                           const uint8_t fingerprint32[32], 
                           std::string& err_out);


bool load_kemtls_pk(const std::string& path,
                    std::vector<uint8_t>& out_pk,
                    uint8_t& out_suite_id, uint8_t& out_alg,
                    uint64_t& out_created_unix,
                    uint8_t out_fingerprint32[32],
                    std::string& err_out);

uint32_t crc32_buf(const uint8_t* data, size_t len);
bool compute_sha256(const uint8_t* data, size_t len, uint8_t out32[32]);
