#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

// PQClean/NIST SUPERCOP signature:
void randombytes(unsigned char *x, unsigned long long xlen)
{
#if defined(__linux__)
    // usa getrandom() si existe (no bloquea una vez inicializado)
    while (xlen > 0) {
        ssize_t n = getrandom(x, xlen, 0);
        if (n < 0) { if (errno == EINTR) continue; break; }
        x += n; xlen -= (unsigned long long)n;
    }
    if (xlen == 0) return;
#endif
    // fallback: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        while (xlen > 0) {
            ssize_t n = read(fd, x, xlen);
            if (n < 0) { if (errno == EINTR) continue; break; }
            x += n; xlen -= (unsigned long long)n;
        }
        close(fd);
    }
    // Si falla, dejamos bytes tal cual; en hardware reemplaza por HAL/TRNG+DRBG.
}
