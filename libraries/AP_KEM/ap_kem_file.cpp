#include "ap_kem_file.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>


extern "C" {
#include "vendor/pqclean/common/sha2.h"  
}


static const uint32_t KEMT_MAGIC = 0x544D454B; 


uint32_t crc32_buf(const uint8_t* data, size_t len) {
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

// --- SHA256 usando PQClean ---
bool compute_sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
    if (!data || !out32) return false;
    sha256(out32, data, len);   
    return true;
}


static bool fsync_dir(const std::string& filepath) {
    size_t p = filepath.find_last_of('/');
    std::string dir = (p==std::string::npos) ? "." : filepath.substr(0,p);
    int dfd = open(dir.c_str(), O_DIRECTORY | O_RDONLY);
    if (dfd < 0) return false;
    int r = fsync(dfd);
    close(dfd);
    return (r == 0);
}

bool save_kemtls_pk_atomic(const std::string& path,
                           const uint8_t* pk, size_t pk_len,
                           uint8_t suite_id, uint8_t alg,
                           uint64_t created_unix,
                           const uint8_t fingerprint32[32],
                           std::string& err_out) {
    std::string tmp = path + ".new";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { err_out = strerror(errno); return false; }

    kemtls_pk_file_hdr hdr{};
    hdr.magic = KEMT_MAGIC;
    hdr.version = 1;
    hdr.suite_id = suite_id;
    hdr.alg = alg;
    hdr.created_unix = created_unix;
    hdr.pk_len = (uint32_t)pk_len;
    if (fingerprint32) memcpy(hdr.pk_fingerprint, fingerprint32, 32);
    else {

        uint8_t fp[32]; memset(fp, 0, 32);
        if (pk && pk_len && compute_sha256(pk, pk_len, fp)) {
            memcpy(hdr.pk_fingerprint, fp, 32);
        } else {
            memset(hdr.pk_fingerprint, 0, 32);
        }
    }
    hdr.crc32 = (pk && pk_len) ? crc32_buf(pk, pk_len) : 0;

    ssize_t w = write(fd, &hdr, sizeof(hdr));
    if (w != (ssize_t)sizeof(hdr)) { err_out = "write hdr failed"; close(fd); return false; }

    if (pk_len) {
        ssize_t w2 = write(fd, pk, pk_len);
        if (w2 != (ssize_t)pk_len) { err_out = "write pk failed"; close(fd); return false; }
    }

    if (fsync(fd) != 0) { err_out = "fsync file failed"; close(fd); return false; }
    close(fd);

    if (rename(tmp.c_str(), path.c_str()) != 0) { err_out = strerror(errno); return false; }

    (void)fsync_dir(path);
    return true;
}

bool load_kemtls_pk(const std::string& path,
                    std::vector<uint8_t>& out_pk,
                    uint8_t& out_suite_id, uint8_t& out_alg,
                    uint64_t& out_created_unix,
                    uint8_t out_fingerprint32[32],
                    std::string& err_out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { err_out = strerror(errno); return false; }

    kemtls_pk_file_hdr hdr{};
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { err_out = "read hdr failed"; fclose(f); return false; }
    if (hdr.magic != KEMT_MAGIC) { err_out = "bad magic"; fclose(f); return false; }
    if (hdr.version != 1) { err_out = "unsupported version"; fclose(f); return false; }
    if (hdr.pk_len > (32u * 1024u)) { err_out = "pk_len too large"; fclose(f); return false; }

    out_pk.resize(hdr.pk_len);
    if (hdr.pk_len) {
        if (fread(out_pk.data(), 1, hdr.pk_len, f) != hdr.pk_len) { err_out = "read pk failed"; fclose(f); return false; }
    }
    fclose(f);


    const uint32_t c = crc32_buf(out_pk.data(), out_pk.size());
    if (c != hdr.crc32) { err_out = "crc mismatch"; return false; }

    out_suite_id = hdr.suite_id;
    out_alg = hdr.alg;
    out_created_unix = hdr.created_unix;
    memcpy(out_fingerprint32, hdr.pk_fingerprint, 32);

    uint8_t local_fp[32]; memset(local_fp, 0, 32);
    compute_sha256(out_pk.data(), out_pk.size(), local_fp);

    bool file_fp_zero = true;
    for (int i=0;i<32;i++) if (hdr.pk_fingerprint[i] != 0) { file_fp_zero = false; break; }

    if (!file_fp_zero && memcmp(local_fp, hdr.pk_fingerprint, 32) != 0) {
        err_out = "fingerprint mismatch";
        return false;
    }
    return true;
}
