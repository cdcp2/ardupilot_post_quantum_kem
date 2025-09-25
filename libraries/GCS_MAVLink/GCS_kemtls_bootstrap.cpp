#include <AP_Filesystem/AP_Filesystem.h>   // IMPORTANTE: antes de usar AP::FS()
#include <cstdint>
#include <string>
#include <vector>
#include <fcntl.h>   // O_RDONLY, O_CREAT, etc.
#include "GCS.h"

static bool vfs_exists(const char* p) {
    AP_Filesystem::stat_t st{};
    return AP::FS().stat(p, st);
}

static bool vfs_copy_file(const char* src, const char* dst) {
    const int in = AP::FS().open(src, O_RDONLY);
    if (in < 0) { return false; }

    std::string tmp = std::string(dst) + ".new";
    const int out = AP::FS().open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC);
    if (out < 0) { AP::FS().close(in); return false; }

    uint8_t buf[4096];
    while (true) {
        const int32_t r = AP::FS().read(in, buf, sizeof(buf));
        if (r == 0) break;                 // EOF
        if (r < 0) {                        // error
            AP::FS().close(in);
            AP::FS().close(out);
            AP::FS().unlink(tmp.c_str());
            return false;
        }
        int32_t off = 0;
        while (off < r) {
            const int32_t w = AP::FS().write(out, buf + off, r - off);
            if (w <= 0) {
                AP::FS().close(in);
                AP::FS().close(out);
                AP::FS().unlink(tmp.c_str());
                return false;
            }
            off += w;
        }
    }
    (void)AP::FS().fsync(out);
    AP::FS().close(out);
    AP::FS().close(in);

    if (AP::FS().rename(tmp.c_str(), dst) != 0) {
        AP::FS().unlink(tmp.c_str());
        return false;
    }
    return true;
}

// Llama esto una sola vez durante el arranque (init de GCS_MAVLINK está bien)
void GCS_MAVLINK::kemtls_pdk_bootstrap_copy_if_missing()
{
    // Usa rutas del VFS (sin '/'): APM/... es la partición persistente
    const char* dst = "APM/CFG/kemtls_pk.bin";
    if (vfs_exists(dst)) {
        return; // ya persistida
    }

    // ROMFS es solo lectura y viene dentro del binario:
    const char* src = "@ROMFS/kemtls/kemtls_pk_default.bin";
    if (!vfs_exists(src)) {
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KEMTLS: default PDK not found in ROMFS");
        return;
    }

    // Asegura directorios (idempotente)
    AP::FS().mkdir("APM");
    AP::FS().mkdir("APM/CFG");

    if (vfs_copy_file(src, dst)) {
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "KEMTLS: PDK default copied to APM/CFG");
    } else {
        GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "KEMTLS: failed to copy default PDK");
    }
}
