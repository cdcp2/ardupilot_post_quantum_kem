#include <stddef.h>
#include <stdint.h>

/* produced by compiling randombytes_linux.c with
   -Drandombytes=PQCLEAN_HQC128_CLEAN_randombytes */
void PQCLEAN_HQC128_CLEAN_randombytes(uint8_t *x, size_t xlen);

/* some PQClean trees end up asking for this when NAMESPACE
   wasn’t set before including randombytes.h */
void PQCLEAN_randombytes(uint8_t *x, size_t xlen) {
    PQCLEAN_HQC128_CLEAN_randombytes(x, xlen);
}
