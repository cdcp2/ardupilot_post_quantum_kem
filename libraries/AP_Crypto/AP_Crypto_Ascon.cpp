#include "AP_CryptoAEAD.h"
#include "ap_config.h"
#include <AP_HAL/AP_HAL_Boards.h>
#include <cstdint>
#include <cstddef>

#if defined(CONFIG_HAL_BOARD) && defined(HAL_BOARD_SITL) && (CONFIG_HAL_BOARD == HAL_BOARD_SITL)
  #include <dlfcn.h>
  #define HAVE_DLOPEN 1
#else
  #define HAVE_DLOPEN 0
  extern "C" {
    void ascon_aead128_sizes(size_t*, size_t*, size_t*);
    int  ascon_aead128_encrypt(unsigned char*, unsigned long long*,
                               const unsigned char*, unsigned long long,
                               const unsigned char*, unsigned long long,
                               const unsigned char*, const unsigned char*);
    int  ascon_aead128_decrypt(unsigned char*, unsigned long long*,
                               const unsigned char*, unsigned long long,
                               const unsigned char*, unsigned long long,
                               const unsigned char*, const unsigned char*);
  }
#endif

// ------------------ Implementación concreta ------------------
class AP_CryptoAEAD_Ascon final : public AP_CryptoAEAD {
public:
    AP_CryptoAEAD_Ascon() { init(); }
#if HAVE_DLOPEN
    ~AP_CryptoAEAD_Ascon() override { if (handle_) dlclose(handle_); }
#endif

    bool sizes(AP_AEAD_Sizes& out) const override {
#if HAVE_DLOPEN
        if (!sz_) return false;
        size_t k=0,n=0,t=0; sz_(&k,&n,&t); out={k,n,t}; return true;
#else
        size_t k=0,n=0,t=0; ascon_aead128_sizes(&k,&n,&t); out={k,n,t}; return true;
#endif
    }

    bool encrypt(uint8_t* c, size_t& clen,
                 const uint8_t* m, size_t mlen,
                 const uint8_t* ad, size_t adlen,
                 const uint8_t* npub,
                 const uint8_t* key) override {
        if (!ok_) return false;
        unsigned long long L=0;
#if HAVE_DLOPEN
        if (enc_((unsigned char*)c,&L,m,mlen,ad,adlen,npub,key)!=0) return false;
#else
        if (ascon_aead128_encrypt((unsigned char*)c,&L,m,mlen,ad,adlen,npub,key)!=0) return false;
#endif
        clen = (size_t)L; return true;
    }

    bool decrypt(uint8_t* m, size_t& mlen,
                 const uint8_t* c, size_t clen,
                 const uint8_t* ad, size_t adlen,
                 const uint8_t* npub,
                 const uint8_t* key) override {
        if (!ok_) return false;
        unsigned long long L=0;
#if HAVE_DLOPEN
        if (dec_((unsigned char*)m,&L,c,clen,ad,adlen,npub,key)!=0) return false;
#else
        if (ascon_aead128_decrypt((unsigned char*)m,&L,c,clen,ad,adlen,npub,key)!=0) return false;
#endif
        mlen = (size_t)L; return true;
    }

private:
    void init() {
#if HAVE_DLOPEN
        handle_ = dlopen("libascon_aead.so", RTLD_NOW);
        if (!handle_) return;
        sz_  = (sz_fn)dlsym(handle_, "ascon_aead128_sizes");
        enc_ = (enc_fn)dlsym(handle_, "ascon_aead128_encrypt");
        dec_ = (dec_fn)dlsym(handle_, "ascon_aead128_decrypt");
        ok_ = (sz_ && enc_ && dec_);
#else
        ok_ = true;
#endif
    }

#if HAVE_DLOPEN
    using sz_fn  = void (*)(size_t*,size_t*,size_t*);
    using enc_fn = int (*)(unsigned char*, unsigned long long*,
                           const unsigned char*, unsigned long long,
                           const unsigned char*, unsigned long long,
                           const unsigned char*, const unsigned char*);
    using dec_fn = int (*)(unsigned char*, unsigned long long*,
                           const unsigned char*, unsigned long long,
                           const unsigned char*, unsigned long long,
                           const unsigned char*, const unsigned char*);
    void* handle_ = nullptr;
    sz_fn  sz_ = nullptr;
    enc_fn enc_ = nullptr;
    dec_fn dec_ = nullptr;
#endif
    bool ok_ = false;
};

// --------- Fábrica (ya declarada en el .h) ----------
static AP_CryptoAEAD_Ascon g_ascon_aead;
AP_CryptoAEAD* AP_Crypto_GetAEAD_Ascon() { return &g_ascon_aead; }
