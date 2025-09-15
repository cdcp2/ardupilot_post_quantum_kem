#include "Copter.h"

#include "GCS_MAVLink_Copter.h"
#include <AP_RPM/AP_RPM_config.h>
#include <AP_EFI/AP_EFI_config.h>
#include <AP_Param/AP_Param.h> 
#include "AP_Crypto/AP_CryptoAEAD.h"
#include <AP_Math/AP_Math.h> 
#include <AP_Math/crc.h> 

#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
  #define CRYPTO_HAVE_DLOPEN 1
  #include <dlfcn.h>
#else
  #define CRYPTO_HAVE_DLOPEN 0
#endif

static inline uint32_t now_ms() {
    return AP_HAL::millis(); 
}

// --- OpenSSL (libcrypto) via dlopen para HKDF/HMAC-SHA256 en SITL ---
#if CRYPTO_HAVE_DLOPEN
static void* crypto_dl = nullptr;
using EVP_MD = void; 
using HMAC_fn = unsigned char* (*)(const EVP_MD*, const void*, int,
                                   const unsigned char*, size_t,
                                   unsigned char*, unsigned int*);
using EVP_sha256_fn = const EVP_MD* (*)();

static HMAC_fn        p_HMAC        = nullptr;
static EVP_sha256_fn  p_EVP_sha256  = nullptr;

static bool hkdf_crypto_init()
{
    if (crypto_dl && p_HMAC && p_EVP_sha256) return true;
    const char* cands[] = {"libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"};
    for (auto so : cands) {
        crypto_dl = dlopen(so, RTLD_NOW);
        if (crypto_dl) break;
    }
    if (!crypto_dl) return false;

    p_HMAC       = (HMAC_fn)dlsym(crypto_dl, "HMAC");
    p_EVP_sha256 = (EVP_sha256_fn)dlsym(crypto_dl, "EVP_sha256");
    return (p_HMAC && p_EVP_sha256);
}

#endif

static inline void hmac_sha256(const uint8_t* key, size_t keylen,
                               const uint8_t* data, size_t datalen,
                               uint8_t out[32])
{
#if CRYPTO_HAVE_DLOPEN
    if (!hkdf_crypto_init()) { memset(out, 0, 32); return; }
    unsigned int olen = 0;
    p_HMAC(p_EVP_sha256(), key, (int)keylen, data, datalen, out, &olen);
    if (olen != 32) { memset(out, 0, 32); }  // por seguridad
#else
    // TODO: en hardware real, enlaza contra tu implementación/driver de HMAC.
    // Por ahora, si no hay backend, deja ceros (evita crash en build fuera de SITL).
    std::memset(out, 0, 32);
#endif
}



// OJO: NO ‘var_info’, sino ‘var_info_crypto’
const AP_Param::GroupInfo GCS_MAVLINK_Copter::var_info_crypto[] = {
    AP_GROUPINFO("CRYPTO_ON",  1, GCS_MAVLINK_Copter, _crypto_on, 0),
    AP_GROUPINFO("CRYPTO_ALG", 2, GCS_MAVLINK_Copter, _crypto_alg, 1),
    AP_GROUPINFO("CRYPTO_TTL", 3, GCS_MAVLINK_Copter, _crypto_ttl_ms, 600000),
    AP_GROUPINFO("CRYPTO_RATE",4, GCS_MAVLINK_Copter, _crypto_rate_pps, 50),
    AP_GROUPINFO("CRYPTO_SID", 5, GCS_MAVLINK_Copter, _crypto_session, 1),
    AP_GROUPEND
};


// ---- AEAD backend ----
typedef void (*ascon_sizes_t)(size_t*, size_t*, size_t*);
typedef int  (*ascon_enc_t)(unsigned char*, unsigned long long*,
                            const unsigned char*, unsigned long long,
                            const unsigned char*, unsigned long long,
                            const unsigned char*, const unsigned char*);
typedef int  (*ascon_dec_t)(unsigned char*, unsigned long long*,
                            const unsigned char*, unsigned long long,
                            const unsigned char*, unsigned long long,
                            const unsigned char*, const unsigned char*);

#if CRYPTO_HAVE_DLOPEN
static void* ascon_dl = nullptr;
static ascon_sizes_t ascon_sizes = nullptr;
static ascon_enc_t   ascon_enc   = nullptr;
static ascon_dec_t   ascon_dec   = nullptr;
#else
extern "C" {
    // Si compilas estático en board real, declara aquí (o incluye el header)
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

bool GCS_MAVLINK_Copter::aead_init_backend() {
    if (aead_ready_) return true;
#if CRYPTO_HAVE_DLOPEN
    ascon_dl = dlopen("libascon_aead.so", RTLD_NOW);
    if (!ascon_dl) return false;
    ascon_sizes = (ascon_sizes_t)dlsym(ascon_dl, "ascon_aead128_sizes");
    ascon_enc   = (ascon_enc_t)  dlsym(ascon_dl, "ascon_aead128_encrypt");
    ascon_dec   = (ascon_dec_t)  dlsym(ascon_dl, "ascon_aead128_decrypt");
    if (!ascon_sizes || !ascon_enc || !ascon_dec) return false;
#else
    // Enlace estático
#endif
    aead_ready_ = true;
    return true;
}

bool GCS_MAVLINK_Copter::aead_sizes(AP_AEAD_Sizes& out) const {
#if CRYPTO_HAVE_DLOPEN
    if (!ascon_sizes) return false;
    size_t k=0,n=0,t=0; ascon_sizes(&k,&n,&t);
    out.key=k; out.npub=n; out.tag=t; return true;
#else
    size_t k=0,n=0,t=0; ascon_aead128_sizes(&k,&n,&t);
    out.key=k; out.npub=n; out.tag=t; return true;
#endif
}

bool GCS_MAVLINK_Copter::aead_encrypt(uint8_t* c, size_t& clen,
                                      const uint8_t* m, size_t mlen,
                                      const uint8_t* ad, size_t adlen,
                                      const uint8_t* npub,
                                      const uint8_t* key) {
    if (!aead_init_backend()) return false;
    unsigned long long outlen = 0;
#if CRYPTO_HAVE_DLOPEN
    if (ascon_enc((unsigned char*)c,&outlen, m, (unsigned long long)mlen,
                  ad, (unsigned long long)adlen, npub, key) != 0) return false;
#else
    if (ascon_aead128_encrypt((unsigned char*)c,&outlen, m, (unsigned long long)mlen,
                              ad, (unsigned long long)adlen, npub, key) != 0) return false;
#endif
    clen = (size_t)outlen; return true;
}

void GCS_MAVLINK_Copter::nonce_from_seq_tx(uint16_t seq, uint8_t out[16]) const {
    memcpy(out, _sess.nonce_base_tx, 16);
    out[0] = uint8_t(seq & 0xFF);
    out[1] = uint8_t(seq >> 8);
    out[2] = (uint8_t)mavlink_system.sysid;
    out[3] = (uint8_t)mavlink_system.compid;
}
void GCS_MAVLINK_Copter::nonce_from_seq_rx(uint16_t seq, uint8_t out[16]) const {
    memcpy(out, _sess.nonce_base_rx, 16);
    out[0] = uint8_t(seq & 0xFF);
    out[1] = uint8_t(seq >> 8);
    out[2] = (uint8_t)mavlink_system.sysid;
    out[3] = (uint8_t)mavlink_system.compid;
}


void GCS_MAVLINK_Copter::send_msg_raw(const mavlink_message_t& m)
{
    uint8_t buf[MAVLINK_MAX_PACKET_LEN];
    const uint16_t len = mavlink_msg_to_send_buffer(buf, &m);

    // lock necesita (chan, len)
    comm_send_lock(chan, len);
    comm_send_buffer(chan, buf, len);
    comm_send_unlock(chan);
}

void GCS_MAVLINK_Copter::handle_crypto_pkt(const mavlink_message_t& msg)
{
    crypto_init_if_needed();

    
    mavlink_crypto_pkt_t p{};
    mavlink_msg_crypto_pkt_decode(&msg, &p);

    
    if (p.alg != AP_AEAD_ALG_ASCON128)  {
        
        return;
    }

    
    AP_CryptoAEAD* aead = AP_Crypto_GetAEAD_Ascon();
    if (!aead) { return; }

    
    uint8_t ad[8]; unsigned adlen = 0;

    uint8_t plain[MAVLINK_MAX_PACKET_LEN] = {0};
    size_t mlen = 0;
    if (!aead->decrypt(plain, mlen,
                       p.cipher, p.cipher_len,
                       (adlen ? ad : nullptr), adlen,
                       p.nonce, _sess.key)) {
        // opcional: STATUS fallo de decrypt
        return;
    }

    mavlink_message_t inner{};
    mavlink_status_t  st{};
    for (size_t i = 0; i < mlen; i++) {
        if (mavlink_parse_char(chan, plain[i], &inner, &st)) {
            this->handle_message(inner);
        }
    }
}


bool GCS_MAVLINK_Copter::aead_decrypt(uint8_t* m, size_t& mlen,
                                      const uint8_t* c, size_t clen,
                                      const uint8_t* ad, size_t adlen,
                                      const uint8_t* npub,
                                      const uint8_t* key) {
    if (!aead_init_backend()) return false;
    unsigned long long outlen = 0;
#if CRYPTO_HAVE_DLOPEN
    if (ascon_dec((unsigned char*)m,&outlen, c, (unsigned long long)clen,
                  ad, (unsigned long long)adlen, npub, key) != 0) return false;
#else
    if (ascon_aead128_decrypt((unsigned char*)m,&outlen, c, (unsigned long long)clen,
                              ad, (unsigned long long)adlen, npub, key) != 0) return false;
#endif
    mlen = (size_t)outlen; return true;
}

// ---- HQC backend (solo usamos enc(pk)-> (ct, ss)) ----
#if CRYPTO_HAVE_DLOPEN
static void* hqc_dl = nullptr;
#endif

bool GCS_MAVLINK_Copter::hqc_init_backend() {
    if (hqc_ready_) return true;
#if CRYPTO_HAVE_DLOPEN
    hqc_dl = dlopen("libpqc_hqc128.so", RTLD_NOW);
    if (!hqc_dl) return false;
    hqc_enc_ = (hqc_enc_t)dlsym(hqc_dl, "pqc_hqc128_enc");
    if (!hqc_enc_) return false;
#else
extern "C" int pqc_hqc128_enc(uint8_t*, uint8_t*, const uint8_t*);
    hqc_enc_ = pqc_hqc128_enc;
#endif
    hqc_ready_ = (hqc_enc_ != nullptr);
    return hqc_ready_;
}

void GCS_MAVLINK_Copter::crypto_init_if_needed() {
    if (!crypto_params_registered_) {
        // Registra el grupo de parámetros de ESTA clase
        AP_Param::setup_object_defaults(this, var_info_crypto);
        crypto_params_registered_ = true;
    }

    if (!_rate_last_ms) _rate_last_ms = now_ms();
    if (!_sess.active) {
        _sess.session_id = (uint8_t)_crypto_session.get();
        _sess.start_ms = 0;
        _sess.rx_last_seq = 0;
        _sess.tx_next_seq = 1;
        memset(_sess.key, 0, sizeof(_sess.key));
        memset(_sess.nonce_base, 0, sizeof(_sess.nonce_base));
    }
}

bool GCS_MAVLINK_Copter::crypto_gate_open() const {
    if (_crypto_on.get() == 0) return false;
    if (_crypto_alg.get() != AP_AEAD_ALG_ASCON128) return false;
    if (!_sess.active) return false;
    // TTL
    if (_crypto_ttl_ms.get() > 0 && _sess.start_ms > 0) {
        if ((uint32_t)(now_ms() - _sess.start_ms) > (uint32_t)_crypto_ttl_ms.get()) return false;
    }
    return true;
}

// Token bucket simple por segundo
bool GCS_MAVLINK_Copter::crypto_rate_allow() {
    const uint32_t now = now_ms();
    if (now - _rate_last_ms >= 1000) {
        _rate_last_ms = now;
        _rate_tokens = (uint32_t)_crypto_rate_pps.get();
    }
    if (_rate_tokens == 0) return false;
    _rate_tokens--;
    return true;
}

void GCS_MAVLINK_Copter::nonce_from_seq(uint16_t seq, uint8_t out16[16]) const {
    // Nonce = base (16B) con los bytes 0..1 xor seq LE
    memcpy(out16, _sess.nonce_base, 16);
    out16[0] ^= (uint8_t)(seq & 0xFF);
    out16[1] ^= (uint8_t)(seq >> 8);
    // También ligamos sysid/compid en bytes 2..3 para unicidad por canal
    out16[2] ^= (uint8_t)mavlink_system.sysid;
    out16[3] ^= (uint8_t)mavlink_system.compid;
}

void GCS_MAVLINK_Copter::build_ad(uint8_t session, uint16_t seq, uint8_t out8[8]) const {
    // AD v1: [0x01][sysid][compid][session][seq_le][msgid_le]
    out8[0] = 1;
    out8[1] = (uint8_t)mavlink_system.sysid;
    out8[2] = (uint8_t)mavlink_system.compid;
    out8[3] = session;
    out8[4] = (uint8_t)(seq & 0xFF);
    out8[5] = (uint8_t)(seq >> 8);
    out8[6] = (uint8_t)(MAVLINK_MSG_ID_CRYPTO_PKT & 0xFF);
    out8[7] = (uint8_t)(MAVLINK_MSG_ID_CRYPTO_PKT >> 8);
}

// --- Allowlist de mensajes "sin firma" permitidos ---
bool GCS_MAVLINK_Copter::is_allowlisted_unsigned(uint32_t msgid)
{
    switch (msgid) {
    case MAVLINK_MSG_ID_HEARTBEAT:
    case MAVLINK_MSG_ID_STATUSTEXT:
#ifdef MAVLINK_MSG_ID_HQC_HELLO
    case MAVLINK_MSG_ID_HQC_HELLO:
    case MAVLINK_MSG_ID_HQC_PK_CHUNK:
    case MAVLINK_MSG_ID_HQC_CT_ACK:
    case MAVLINK_MSG_ID_HQC_FINISH:
    case MAVLINK_MSG_ID_HQC_STATUS:
#endif
        return true;
    default:
        return false;
    }
}

// --- Callback que MAVLink invoca para decidir si acepta un paquete no firmado ---
bool GCS_MAVLINK_Copter::accept_unsigned_cb(const mavlink_status_t* status, uint32_t msgid)
{
    (void)status; // evita warning -Wunused-parameter con -Werror
    return GCS_MAVLINK_Copter::is_allowlisted_unsigned(msgid);
}



static void hkdf_sha256_extract(const uint8_t* salt, size_t saltlen,
                                const uint8_t* ikm, size_t ikmlen,
                                uint8_t prk[32]) {
    hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

static void hkdf_sha256_expand(const uint8_t prk[32],
                               const uint8_t* info, size_t infolen,
                               uint8_t* okm, size_t L) {
    uint8_t T[32]; size_t Tlen = 0;
    uint8_t ctr = 1; size_t off = 0;
    while (off < L) {
        // T = HMAC(PRK, T || info || ctr)
        uint8_t buf[32 + 64 + 1]; // T(32) + info(max ~64) + 1
        size_t pos = 0;
        if (Tlen) { memcpy(buf+pos, T, Tlen); pos += Tlen; }
        if (info && infolen) { memcpy(buf+pos, info, infolen); pos += infolen; }
        buf[pos++] = ctr++;
        hmac_sha256(prk, 32, buf, pos, T);
        Tlen = 32;
        size_t n = MIN((size_t)32, L - off);
        memcpy(okm + off, T, n);
        off += n;
    }
}


void GCS_MAVLINK_Copter::derive_session_key_from_ss(const uint8_t ss[32],
                                                    const uint8_t salt16[16],
                                                    uint8_t key16_out[16],
                                                    uint8_t nonce_base16_out[16]) {
    const uint8_t info[] = "ardupilot-hqc-v1";
    uint8_t prk[32], okm[32];
    hkdf_sha256_extract(salt16, 16, ss, 32, prk);
    hkdf_sha256_expand(prk, info, sizeof(info)-1, okm, sizeof(okm));
    memcpy(key16_out,        okm,      16);
    memcpy(nonce_base16_out, okm + 16, 16);
}



bool GCS_MAVLINK_Copter::send_crypto_pkt_wrapped(const mavlink_message_t& inner)
{
    if (!crypto_gate_open()) return false;
    if (!crypto_rate_allow()) return false;

    // Serializa inner → buffer
    uint8_t inner_buf[240]; // deja margen
    const uint16_t inner_len = mavlink_msg_to_send_buffer(inner_buf, &inner);
    if (inner_len == 0 || inner_len > 220) return false; // ajusta si necesitas más

    // Seq + AD + Nonce
    const uint16_t seq = _sess.tx_next_seq++;
    uint8_t ad[8]; build_ad(_sess.session_id, seq, ad);
    uint8_t nonce[16]; nonce_from_seq(seq, nonce);

    // Encrypt
    uint8_t cipher[240]; size_t clen = sizeof(cipher);
    if (!aead_encrypt(cipher, clen, inner_buf, inner_len,
                      ad, sizeof(ad), nonce, _sess.key)) return false;

    // Empaquetar CRYPTO_PKT
    mavlink_message_t msg{};
    mavlink_crypto_pkt_t pkt{};
    pkt.seq = seq;
    pkt.cipher_len = (uint16_t)clen;
    pkt.target_system = mavlink_system.sysid;
    pkt.target_component = mavlink_system.compid;
    pkt.alg = 1; // ASCON128
    pkt.session = _sess.session_id;
    memcpy(pkt.nonce, nonce, 16);
    memset(pkt.cipher, 0, sizeof(pkt.cipher));
    memcpy(pkt.cipher, cipher, clen);

    mavlink_msg_crypto_pkt_encode(mavlink_system.sysid, mavlink_system.compid, &msg, &pkt);
    send_msg_raw(msg);
    return true;
}

void GCS_MAVLINK_Copter::handle_hqc_hello(const mavlink_message_t& msg)
{
    // Inicializa entornos
    crypto_init_if_needed();
    if (!hqc_init_backend()) {
        // responder rechazando por backend no disponible
        mavlink_message_t ack{};
        mavlink_hqc_hello_t in{};
        mavlink_msg_hqc_hello_decode(&msg, &in);

        mavlink_hqc_hello_ack_t out{};
        out.session_id = in.session_id;
        out.mtu = 220;
        out.window = 8;
        out.required_alg = 1; // ASCON128
        out.accept = 0;
        out.status = HQC_KEX_ENC_UNAV;
        mavlink_msg_hqc_hello_ack_encode(mavlink_system.sysid, mavlink_system.compid, &ack, &out);
        send_msg_raw(ack);
        return;
    }

    // Guardar parámetros de sesión
    hqc_.reset();
    mavlink_hqc_hello_t in{};
    mavlink_msg_hqc_hello_decode(&msg, &in);
    hqc_.session_id = in.session_id;
    hqc_.pk_len = in.pk_len;
    hqc_.ct_len = in.ct_len;
    hqc_.version = in.version;
    hqc_.suite_id = in.suite_id;
    hqc_.flags = in.flags;
    memcpy(hqc_.salt, in.handshake_salt, 16);

    // Reservar buffer para PK
    if (hqc_.pk_len == 0 || hqc_.pk_len > 65536) { // sanity
        // Responder BAD_LEN
        mavlink_message_t st{};
        mavlink_hqc_status_t s{};
        s.session_id = hqc_.session_id;
        s.value = hqc_.pk_len;
        s.status = HQC_KEX_BAD_LEN;
        s.detail = 0;
        mavlink_msg_hqc_status_encode(mavlink_system.sysid, mavlink_system.compid, &st, &s);
        send_msg_raw(st);
        return;
    }
    hqc_.pk = (uint8_t*)malloc(hqc_.pk_len);
    if (!hqc_.pk) {
        mavlink_message_t st{};
        mavlink_hqc_status_t s{};
        s.session_id = hqc_.session_id;
        s.value = 0;
        s.status = HQC_KEX_INTERNAL;
        s.detail = 1;
        mavlink_msg_hqc_status_encode(mavlink_system.sysid, mavlink_system.compid, &st, &s);
        send_msg_raw(st);
        return;
    }

    // ACK de hello (aceptamos)
    mavlink_message_t ack{};
    mavlink_hqc_hello_ack_t out{};
    out.session_id = hqc_.session_id;
    out.mtu    = hqc_.mtu;
    out.window = hqc_.window;
    out.required_alg = 1; // ASCON128
    out.accept = 1;
    out.status = HQC_KEX_IN_PROGRESS;
    mavlink_msg_hqc_hello_ack_encode(mavlink_system.sysid, mavlink_system.compid, &ack, &out);
    send_msg_raw(ack);
}

static inline uint32_t crc32_ap(const uint8_t* buf, size_t len)
{
    uint32_t crc = 0;
    crc ^= ~0U;
    crc = crc_crc32(crc, buf, (uint32_t)len);
    crc ^= ~0U;
    return crc;
}

void GCS_MAVLINK_Copter::handle_hqc_pk_chunk(const mavlink_message_t& msg)
{
    if (!hqc_ready_) return;

    mavlink_hqc_pk_chunk_t c{};
    mavlink_msg_hqc_pk_chunk_decode(&msg, &c);
    if (c.session_id != hqc_.session_id) return;

    // bounds
    if ((uint64_t)c.offset + c.count > hqc_.pk_len) {
        mavlink_message_t st{};
        mavlink_hqc_status_t s{};
        s.session_id = hqc_.session_id; s.value = c.offset; s.status = HQC_KEX_BAD_LEN; s.detail=2;
        mavlink_msg_hqc_status_encode(mavlink_system.sysid, mavlink_system.compid, &st, &s);
        send_msg_raw(st);
        return;
    }

    memcpy(hqc_.pk + c.offset, c.data, c.count);
    hqc_.pk_rcvd += c.count;

    // Progreso
    if ((hqc_.pk_rcvd % (hqc_.mtu * 4)) == 0 || hqc_.pk_rcvd == hqc_.pk_len) {
        mavlink_message_t st{};
        mavlink_hqc_status_t s{};
        s.session_id = hqc_.session_id; s.value = hqc_.pk_rcvd; s.status = HQC_KEX_IN_PROGRESS; s.detail=0;
        mavlink_msg_hqc_status_encode(mavlink_system.sysid, mavlink_system.compid, &st, &s);
        send_msg_raw(st);
    }

    // ¿PK completa? → enc()
    if (hqc_.pk_rcvd == hqc_.pk_len) {

        // Estimar ct_len si no vino
        if (hqc_.ct_len == 0 || hqc_.ct_len > 65536) {
            if (hqc_.ct_len == 0) {
                switch (hqc_.suite_id) {
                    case 1: hqc_.ct_len = 4433;  break; // HQC-128
                    case 3: hqc_.ct_len = 8978;  break; // HQC-192
                    case 5: hqc_.ct_len = 14421; break; // HQC-256
                    default: hqc_.ct_len = 4433; break; // fallback sensato
                }
            } else {
                hqc_.ct_len = MIN(hqc_.ct_len, (uint32_t)65536U);
            }
        }

        // Reservar CT UNA sola vez
        if (hqc_.ct) { free(hqc_.ct); hqc_.ct = nullptr; }
        hqc_.ct = (uint8_t*)malloc(hqc_.ct_len);
        if (!hqc_.ct) {
            mavlink_message_t st{};
            mavlink_hqc_status_t s{};
            s.session_id = hqc_.session_id; s.value = 0; s.status = HQC_KEX_INTERNAL; s.detail=1;
            mavlink_msg_hqc_status_encode(mavlink_system.sysid, mavlink_system.compid, &st, &s);
            send_msg_raw(st);
            return;
        }

        // Encapsular: genera CT y SS (64B en HQC)
        uint8_t ss_local[64] = {0};
        if (!hqc_enc_ || hqc_enc_(hqc_.ct, ss_local, hqc_.pk) != 0) {
            mavlink_message_t st{};
            mavlink_hqc_status_t s{};
            s.session_id = hqc_.session_id; s.value = 0; s.status = HQC_KEX_INTERNAL; s.detail=3;
            mavlink_msg_hqc_status_encode(mavlink_system.sysid, mavlink_system.compid, &st, &s);
            send_msg_raw(st);
            return;
        }

        // Guarda SS y CRCs para FINISH
        memcpy(hqc_.ss, ss_local, sizeof(ss_local)); // hqc_.ss debe ser [64]
        hqc_.pk_crc = crc32_ap(hqc_.pk, hqc_.pk_len);
        hqc_.ct_crc = crc32_ap(hqc_.ct, hqc_.ct_len);


        const uint16_t mtu = hqc_.mtu ? hqc_.mtu : 220;
        const uint32_t n_chunks = (hqc_.ct_len + mtu - 1U) / mtu;
        hqc_.ct_acked.assign(n_chunks, 0);

        send_text(MAV_SEVERITY_INFO,
                "HQC_CT init len=%u mtu=%u chunks=%u",
                (unsigned)hqc_.ct_len, (unsigned)mtu, (unsigned)n_chunks);

        // dispara las dos primeras ventanas para evitar estar esperando el primer ACK:
        for (uint32_t off = 0; off < MIN<uint32_t>(hqc_.ct_len, mtu*64U); off += mtu) {
            resend_ct_chunk_at(off);
        }

        // Enviar CT fragmentado
        send_hqc_ct_chunks();
    }
}


void GCS_MAVLINK_Copter::resend_ct_window(uint32_t base, uint32_t mask)
{
    if (!hqc_.ct || hqc_.ct_len == 0) return;
    const uint16_t mtu = hqc_.mtu;
    for (uint8_t i = 0; i < 32; i++) {
        const uint32_t off = base + (uint32_t)i * mtu;
        if (off >= hqc_.ct_len) break;
        const bool received = (mask >> i) & 0x1;
        if (!received) {
            const uint16_t count = (uint16_t)MIN<uint32_t>(mtu, hqc_.ct_len - off);
            mavlink_message_t m{};
            mavlink_hqc_ct_chunk_t out{};
            out.session_id = hqc_.session_id;
            out.offset = off;
            out.count = count;
            memset(out.data, 0, sizeof(out.data));
            memcpy(out.data, hqc_.ct + off, count);
            mavlink_msg_hqc_ct_chunk_encode(mavlink_system.sysid, mavlink_system.compid, &m, &out);
            send_msg_raw(m);
        }
    }
}


void GCS_MAVLINK_Copter::send_hqc_ct_chunks()
{
    if (!hqc_.ct || hqc_.ct_len == 0) return;
    const uint16_t mtu = hqc_.mtu;
    for (uint32_t off = 0; off < hqc_.ct_len; off += mtu) {
        const uint32_t idx = off / mtu;
        if (idx < hqc_.ct_acked.size() && hqc_.ct_acked[idx]) {
            continue; // ya ACK
        }
        resend_ct_chunk_at(off);
    }
}

void GCS_MAVLINK_Copter::resend_ct_chunk_at(uint32_t off)
{
    if (!hqc_.ct || off >= hqc_.ct_len) return;
    const uint16_t mtu = hqc_.mtu ? hqc_.mtu : 220;
    const uint16_t count = (uint16_t)MIN<uint32_t>(mtu, hqc_.ct_len - off);

    // DEBUG
    send_text(MAV_SEVERITY_DEBUG, "HQC_CT_CHUNK TX off=%u n=%u", (unsigned)off, (unsigned)count);

    mavlink_message_t m{};
    mavlink_hqc_ct_chunk_t out{};
    out.session_id = hqc_.session_id;
    out.offset = off;
    out.count = count;
    memset(out.data, 0, sizeof(out.data));
    memcpy(out.data, hqc_.ct + off, count);
    mavlink_msg_hqc_ct_chunk_encode(mavlink_system.sysid, mavlink_system.compid, &m, &out);
    send_msg_raw(m);
}


void GCS_MAVLINK_Copter::handle_hqc_ct_ack(const mavlink_message_t& msg)
{
    mavlink_hqc_ct_ack_t a{};
    mavlink_msg_hqc_ct_ack_decode(&msg, &a);
    if (a.session_id != hqc_.session_id) return;

    const uint16_t mtu = hqc_.mtu ? hqc_.mtu : 220;
    const uint32_t base_idx = a.base / mtu;

    send_text(MAV_SEVERITY_DEBUG, "HQC_CT_ACK base=%u mask=0x%08X",
              (unsigned)a.base, (unsigned)a.mask);

    for (uint8_t i = 0; i < 32; i++) {
        const uint32_t idx = base_idx + i;
        if (idx >= hqc_.ct_acked.size()) break;
        if ((a.mask >> i) & 1U) { hqc_.ct_acked[idx] = 1; }
    }
    resend_ct_window(a.base, a.mask);
}


void GCS_MAVLINK_Copter::send_hqc_status(uint8_t status, uint32_t value, uint8_t detail)
{
    mavlink_message_t st{};
    mavlink_hqc_status_t s{};
    s.session_id = hqc_.session_id;
    s.value      = value;
    s.status     = status;
    s.detail     = detail;

    mavlink_msg_hqc_status_encode(mavlink_system.sysid,
                                  mavlink_system.compid,
                                  &st, &s);
    send_msg_raw(st);
}



// helpers para logs compactos
static inline uint32_t u32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void print_hex16(GCS_MAVLINK_Copter* g, const char* tag, const uint8_t* b) {
    g->send_text(MAV_SEVERITY_INFO, "%s=%08x %08x %08x %08x",
                 tag, u32le(b), u32le(b+4), u32le(b+8), u32le(b+12));
}

void GCS_MAVLINK_Copter::handle_hqc_finish(const mavlink_message_t& msg)
{
    mavlink_hqc_finish_t fin{};
    mavlink_msg_hqc_finish_decode(&msg, &fin);

    send_text(MAV_SEVERITY_INFO,
              "HQC_FINISH sid=%llu len=%u",
              (unsigned long long)fin.session_id,
              (unsigned)fin.tag_len);

    if (fin.session_id != hqc_.session_id || fin.tag_len != 32) {
        send_hqc_status(HQC_KEX_BAD_LEN, /*detail=*/9, /*value=*/0);
        return;
    }

    // ---- transcript v1 (tu mismo layout, packed) ----
    struct __attribute__((packed)) FinishBlob {
        uint8_t  version, suite_id;
        uint64_t session_id;
        uint8_t  salt[16];
        uint32_t pk_len, ct_len, pk_crc, ct_crc;
        uint16_t mtu;
        uint8_t  window, alg;
    } blob;

    blob.version    = hqc_.version;
    blob.suite_id   = hqc_.suite_id;
    blob.session_id = hqc_.session_id;
    memcpy(blob.salt, hqc_.salt, 16);
    blob.pk_len     = hqc_.pk_len;
    blob.ct_len     = hqc_.ct_len;
    blob.pk_crc     = hqc_.pk_crc;
    blob.ct_crc     = hqc_.ct_crc;
    blob.mtu        = hqc_.mtu;
    blob.window     = hqc_.window;
    blob.alg        = AP_AEAD_ALG_ASCON128;

    // ---- LOG entrada para comparar con GCS ----
    send_text(MAV_SEVERITY_INFO, "FIN mtu=%u win=%u pk_len=%u ct_len=%u",
              (unsigned)blob.mtu, (unsigned)blob.window, (unsigned)blob.pk_len, (unsigned)blob.ct_len);
    send_text(MAV_SEVERITY_INFO, "FIN crc pk=%08x ct=%08x", blob.pk_crc, blob.ct_crc);
    print_hex16(this, "FIN salt", blob.salt);
    print_hex16(this, "FIN tag_rx", fin.tag);

    // ---- HKDF con SS=64 (HQC-128 usa SS de 64 bytes) ----
    uint8_t prk64[32], kf64[32], tag64[32];
    hkdf_sha256_extract(hqc_.salt, 16, hqc_.ss, 64, prk64);
    hkdf_sha256_expand(prk64, (const uint8_t*)"ardupilot-hqc-v1:finish", 23, kf64, 32);
    hmac_sha256(kf64, 32, (const uint8_t*)&blob, sizeof(blob), tag64);

    print_hex16(this, "FIN kf64", kf64);
    print_hex16(this, "FIN tag_exp64", tag64);

    bool ok = (memcmp(tag64, fin.tag, 32) == 0);

#if 1 // compat temporal: reintenta con SS=32 si falla (para detectar desalineaciones)
    uint8_t prk32[32], kf32[32], tag32[32];
    bool ok32 = false;
    if (!ok) {
        hkdf_sha256_extract(hqc_.salt, 16, hqc_.ss, 32, prk32);
        hkdf_sha256_expand(prk32, (const uint8_t*)"ardupilot-hqc-v1:finish", 23, kf32, 32);
        hmac_sha256(kf32, 32, (const uint8_t*)&blob, sizeof(blob), tag32);
        print_hex16(this, "FIN kf32", kf32);
        print_hex16(this, "FIN tag_exp32", tag32);
        ok32 = (memcmp(tag32, fin.tag, 32) == 0);
    }
    if (!ok && ok32) {
        send_text(MAV_SEVERITY_WARNING, "HQC_FINISH compat: SS=32 matched; please fix to SS=64");
        // seguimos con prk32 para derivar claves y no bloquear
        memcpy(prk64, prk32, 32);
        ok = true;
    }
#endif

    if (!ok) {
        // NUNCA silencio: status BAD_MAC
        send_hqc_status(HQC_KEX_BAD_LEN, /*detail=*/10, /*value=*/0);
        send_text(MAV_SEVERITY_WARNING, "HQC_FINISH BAD_MAC");
        return;
    }

    // --- derivaciones finales con PRK válido (64 normal o 32 compat) ---
    uint8_t k_sig32[32], k_tx[16], k_rx[16], n_tx[16], n_rx[16];
    hkdf_sha256_expand(prk64, (const uint8_t*)"ardupilot-hqc-v1:sign",          22, k_sig32, 32);
    hkdf_sha256_expand(prk64, (const uint8_t*)"ardupilot-hqc-v1:enc:fc->gcs",   26, k_tx, 16);
    hkdf_sha256_expand(prk64, (const uint8_t*)"ardupilot-hqc-v1:enc:gcs->fc",   26, k_rx, 16);
    hkdf_sha256_expand(prk64, (const uint8_t*)"ardupilot-hqc-v1:nonce:fc->gcs", 28, n_tx, 16);
    hkdf_sha256_expand(prk64, (const uint8_t*)"ardupilot-hqc-v1:nonce:gcs->fc", 28, n_rx, 16);

    // instala claves (tu layout)
    memcpy(_sess.key,        k_rx, 16);
    memcpy(_sess.nonce_base, n_rx, 16);
    _sess.session_id = (uint8_t)_crypto_session.get();
    _sess.active     = true;
    _sess.start_ms   = now_ms();
    _sess.rx_last_seq = 0;
    _sess.tx_next_seq = 1;

    // firma MAVLink2
    static mavlink_signing_streams_t g_streams{};
    static mavlink_signing_t s{}; memset(&s,0,sizeof(s));
    memcpy(s.secret_key, k_sig32, 32);
    s.link_id = _sess.session_id;
    s.flags   = MAVLINK_SIGNING_FLAG_SIGN_OUTGOING;
    s.accept_unsigned_callback = &GCS_MAVLINK_Copter::accept_unsigned_cb;
    memset(&g_streams, 0, sizeof(g_streams));   // reset de anti-replay por link_id

    mavlink_status_t* st = mavlink_get_channel_status(chan);
    st->signing         = &s;
    st->signing_streams = &g_streams;

    send_hqc_status(HQC_KEX_OK, /*detail=*/0, /*value=*/0);
    send_text(MAV_SEVERITY_INFO, "HQC_FINISH OK; gate/signing enabled link_id=%u", (unsigned)s.link_id);
}



MAV_TYPE GCS_Copter::frame_type() const
{
    /*
      for GCS don't give MAV_TYPE_GENERIC as the GCS would have no
      information and won't display UIs such as flight mode
      selection
    */
#if FRAME_CONFIG == HELI_FRAME
    const MAV_TYPE mav_type_default = MAV_TYPE_HELICOPTER;
#else
    const MAV_TYPE mav_type_default = MAV_TYPE_QUADROTOR;
#endif
    if (copter.motors == nullptr) {
        return mav_type_default;
    }
    MAV_TYPE mav_type = copter.motors->get_frame_mav_type();
    if (mav_type == MAV_TYPE_GENERIC) {
        mav_type = mav_type_default;
    }
    return mav_type;
}

uint8_t GCS_MAVLINK_Copter::base_mode() const
{
    uint8_t _base_mode = MAV_MODE_FLAG_STABILIZE_ENABLED;
    // work out the base_mode. This value is not very useful
    // for APM, but we calculate it as best we can so a generic
    // MAVLink enabled ground station can work out something about
    // what the MAV is up to. The actual bit values are highly
    // ambiguous for most of the APM flight modes. In practice, you
    // only get useful information from the custom_mode, which maps to
    // the APM flight mode and has a well defined meaning in the
    // ArduPlane documentation
    if ((copter.pos_control != nullptr) && copter.pos_control->is_active_NE()) {
        _base_mode |= MAV_MODE_FLAG_GUIDED_ENABLED;
        // note that MAV_MODE_FLAG_AUTO_ENABLED does not match what
        // APM does in any mode, as that is defined as "system finds its own goal
        // positions", which APM does not currently do
    }

    // all modes except INITIALISING have some form of manual
    // override if stick mixing is enabled
    _base_mode |= MAV_MODE_FLAG_MANUAL_INPUT_ENABLED;

    // we are armed if we are not initialising
    if (copter.motors != nullptr && copter.motors->armed()) {
        _base_mode |= MAV_MODE_FLAG_SAFETY_ARMED;
    }

    // indicate we have set a custom mode
    _base_mode |= MAV_MODE_FLAG_CUSTOM_MODE_ENABLED;

    return _base_mode;
}

uint32_t GCS_Copter::custom_mode() const
{
    return (uint32_t)copter.flightmode->mode_number();
}

MAV_STATE GCS_MAVLINK_Copter::vehicle_system_status() const
{
    // set system as critical if any failsafe have triggered
    if (copter.any_failsafe_triggered())  {
        return MAV_STATE_CRITICAL;
    }

    if (copter.ap.land_complete) {
        return MAV_STATE_STANDBY;
    }

    if (!copter.ap.initialised) {
    	return MAV_STATE_BOOT;
    }

    return MAV_STATE_ACTIVE;
}


void GCS_MAVLINK_Copter::send_attitude_target()
{
    const Quaternion quat  = copter.attitude_control->get_attitude_target_quat();
    const Vector3f ang_vel = copter.attitude_control->get_attitude_target_ang_vel();
    const float thrust = copter.attitude_control->get_throttle_in();

    const float quat_out[4] {quat.q1, quat.q2, quat.q3, quat.q4};

    // Note: When sending out the attitude_target info. we send out all of info. no matter the mavlink typemask
    // This way we send out the maximum information that can be used by the sending control systems to adapt their generated trajectories
    const uint16_t typemask = 0;    // Ignore nothing

    mavlink_msg_attitude_target_send(
        chan,
        AP_HAL::millis(),       // time since boot (ms)
        typemask,               // Bitmask that tells the system what control dimensions should be ignored by the vehicle
        quat_out,               // Attitude quaternion [w, x, y, z] order, zero-rotation is [1, 0, 0, 0], unit-length
        ang_vel.x,              // roll rate (rad/s)
        ang_vel.y,              // pitch rate (rad/s)
        ang_vel.z,              // yaw rate (rad/s)
        thrust);                // Collective thrust, normalized to 0 .. 1
}

void GCS_MAVLINK_Copter::send_position_target_global_int()
{
    Location target;
    if (!copter.flightmode->get_wp(target)) {
        return;
    }

    // convert altitude frame to AMSL (this may use the terrain database)
    if (!target.change_alt_frame(Location::AltFrame::ABSOLUTE)) {
        return;
    }
    static constexpr uint16_t POSITION_TARGET_TYPEMASK_LAST_BYTE = 0xF000;
    static constexpr uint16_t TYPE_MASK = POSITION_TARGET_TYPEMASK_VX_IGNORE | POSITION_TARGET_TYPEMASK_VY_IGNORE | POSITION_TARGET_TYPEMASK_VZ_IGNORE |
                                          POSITION_TARGET_TYPEMASK_AX_IGNORE | POSITION_TARGET_TYPEMASK_AY_IGNORE | POSITION_TARGET_TYPEMASK_AZ_IGNORE |
                                          POSITION_TARGET_TYPEMASK_YAW_IGNORE | POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE | POSITION_TARGET_TYPEMASK_LAST_BYTE;
    mavlink_msg_position_target_global_int_send(
        chan,
        AP_HAL::millis(), // time_boot_ms
        MAV_FRAME_GLOBAL, // targets are always global altitude
        TYPE_MASK, // ignore everything except the x/y/z components
        target.lat, // latitude as 1e7
        target.lng, // longitude as 1e7
        target.alt * 0.01f, // altitude is sent as a float
        0.0f, // vx
        0.0f, // vy
        0.0f, // vz
        0.0f, // afx
        0.0f, // afy
        0.0f, // afz
        0.0f, // yaw
        0.0f); // yaw_rate
}

void GCS_MAVLINK_Copter::send_position_target_local_ned()
{
#if MODE_GUIDED_ENABLED
    if (!copter.flightmode->in_guided_mode()) {
        return;
    }

    const ModeGuided::SubMode guided_mode = copter.mode_guided.submode();
    Vector3f target_pos_neu_m;
    Vector3f target_vel_neu_ms;
    Vector3f target_accel_neu_mss;
    uint16_t type_mask = 0;

    switch (guided_mode) {
    case ModeGuided::SubMode::Angle:
        // we don't have a local target when in angle mode
        return;
    case ModeGuided::SubMode::TakeOff:
    case ModeGuided::SubMode::WP:
    case ModeGuided::SubMode::Pos:
        type_mask = POSITION_TARGET_TYPEMASK_VX_IGNORE | POSITION_TARGET_TYPEMASK_VY_IGNORE | POSITION_TARGET_TYPEMASK_VZ_IGNORE |
                    POSITION_TARGET_TYPEMASK_AX_IGNORE | POSITION_TARGET_TYPEMASK_AY_IGNORE | POSITION_TARGET_TYPEMASK_AZ_IGNORE |
                    POSITION_TARGET_TYPEMASK_YAW_IGNORE| POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE; // ignore everything except position
        target_pos_neu_m = copter.mode_guided.get_target_pos_NEU_m().tofloat();
        break;
    case ModeGuided::SubMode::PosVelAccel:
        type_mask = POSITION_TARGET_TYPEMASK_YAW_IGNORE| POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE; // ignore everything except position, velocity & acceleration
        target_pos_neu_m = copter.mode_guided.get_target_pos_NEU_m().tofloat();
        target_vel_neu_ms = copter.mode_guided.get_target_vel_NEU_ms();
        target_accel_neu_mss = copter.mode_guided.get_target_accel_NEU_mss();
        break;
    case ModeGuided::SubMode::VelAccel:
        type_mask = POSITION_TARGET_TYPEMASK_X_IGNORE | POSITION_TARGET_TYPEMASK_Y_IGNORE | POSITION_TARGET_TYPEMASK_Z_IGNORE |
                    POSITION_TARGET_TYPEMASK_YAW_IGNORE| POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE; // ignore everything except velocity & acceleration
        target_vel_neu_ms = copter.mode_guided.get_target_vel_NEU_ms();
        target_accel_neu_mss = copter.mode_guided.get_target_accel_NEU_mss();
        break;
    case ModeGuided::SubMode::Accel:
        type_mask = POSITION_TARGET_TYPEMASK_X_IGNORE | POSITION_TARGET_TYPEMASK_Y_IGNORE | POSITION_TARGET_TYPEMASK_Z_IGNORE |
                    POSITION_TARGET_TYPEMASK_VX_IGNORE | POSITION_TARGET_TYPEMASK_VY_IGNORE | POSITION_TARGET_TYPEMASK_VZ_IGNORE |
                    POSITION_TARGET_TYPEMASK_YAW_IGNORE| POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE; // ignore everything except velocity & acceleration
        target_accel_neu_mss = copter.mode_guided.get_target_accel_NEU_mss();
        break;
    }

    mavlink_msg_position_target_local_ned_send(
        chan,
        AP_HAL::millis(), // time boot ms
        MAV_FRAME_LOCAL_NED, 
        type_mask,
        target_pos_neu_m.x,   // x in metres
        target_pos_neu_m.y,   // y in metres
        -target_pos_neu_m.z,  // z in metres NED frame
        target_vel_neu_ms.x,   // vx in m/s
        target_vel_neu_ms.y,   // vy in m/s
        -target_vel_neu_ms.z,  // vz in m/s NED frame
        target_accel_neu_mss.x, // afx in m/s/s
        target_accel_neu_mss.y, // afy in m/s/s
        -target_accel_neu_mss.z,// afz in m/s/s NED frame
        0.0f, // yaw
        0.0f); // yaw_rate
#endif
}

void GCS_MAVLINK_Copter::send_nav_controller_output() const
{
    if (!copter.ap.initialised) {
        return;
    }
    const Vector3f &targets_rad = copter.attitude_control->get_att_target_euler_rad();
    const Mode *flightmode = copter.flightmode;
    mavlink_msg_nav_controller_output_send(
        chan,
        degrees(targets_rad.x),
        degrees(targets_rad.y),
        degrees(targets_rad.z),
        flightmode->wp_bearing_deg(),
        MIN(flightmode->wp_distance_m(), UINT16_MAX),
        copter.pos_control->get_pos_error_U_m(),
        0,
        flightmode->crosstrack_error_m());
}

float GCS_MAVLINK_Copter::vfr_hud_airspeed() const
{
#if AP_AIRSPEED_ENABLED
    // airspeed sensors are best. While the AHRS airspeed_estimate
    // will use an airspeed sensor, that value is constrained by the
    // ground speed. When reporting we should send the true airspeed
    // value if possible:
    if (copter.airspeed.enabled() && copter.airspeed.healthy()) {
        return copter.airspeed.get_airspeed();
    }
#endif
    
    Vector3f airspeed_vec_bf;
    if (AP::ahrs().airspeed_vector_true(airspeed_vec_bf)) {
        // we are running the EKF3 wind estimation code which can give
        // us an airspeed estimate
        return airspeed_vec_bf.length();
    }
    return AP::gps().ground_speed();
}

int16_t GCS_MAVLINK_Copter::vfr_hud_throttle() const
{
    if (copter.motors == nullptr) {
        return 0;
    }
    return (int16_t)(copter.motors->get_throttle() * 100);
}

/*
  send PID tuning message
 */
void GCS_MAVLINK_Copter::send_pid_tuning()
{
    static const PID_TUNING_AXIS axes[] = {
        PID_TUNING_ROLL,
        PID_TUNING_PITCH,
        PID_TUNING_YAW,
        PID_TUNING_ACCZ
    };
    for (uint8_t i=0; i<ARRAY_SIZE(axes); i++) {
        if (!(copter.g.gcs_pid_mask & (1<<(axes[i]-1)))) {
            continue;
        }
        if (!HAVE_PAYLOAD_SPACE(chan, PID_TUNING)) {
            return;
        }
        const AP_PIDInfo *pid_info = nullptr;
        switch (axes[i]) {
        case PID_TUNING_ROLL:
            pid_info = &copter.attitude_control->get_rate_roll_pid().get_pid_info();
            break;
        case PID_TUNING_PITCH:
            pid_info = &copter.attitude_control->get_rate_pitch_pid().get_pid_info();
            break;
        case PID_TUNING_YAW:
            pid_info = &copter.attitude_control->get_rate_yaw_pid().get_pid_info();
            break;
        case PID_TUNING_ACCZ:
            pid_info = &copter.pos_control->get_accel_U_pid().get_pid_info();
            break;
        default:
            continue;
        }
        if (pid_info != nullptr) {
            mavlink_msg_pid_tuning_send(chan,
                                        axes[i],
                                        pid_info->target,
                                        pid_info->actual,
                                        pid_info->FF,
                                        pid_info->P,
                                        pid_info->I,
                                        pid_info->D,
                                        pid_info->slew_rate,
                                        pid_info->Dmod);
        }
    }
}

#if AP_WINCH_ENABLED
// send winch status message
void GCS_MAVLINK_Copter::send_winch_status() const
{
    AP_Winch *winch = AP::winch();
    if (winch == nullptr) {
        return;
    }
    winch->send_status(*this);
}
#endif

bool GCS_Copter::vehicle_initialised() const {
    return copter.ap.initialised;
}

// try to send a message, return false if it wasn't sent
bool GCS_MAVLINK_Copter::try_send_message(enum ap_message id)
{
    switch(id) {

#if AP_TERRAIN_AVAILABLE
    case MSG_TERRAIN_REQUEST:
        CHECK_PAYLOAD_SIZE(TERRAIN_REQUEST);
        copter.terrain.send_request(chan);
        break;
    case MSG_TERRAIN_REPORT:
        CHECK_PAYLOAD_SIZE(TERRAIN_REPORT);
        copter.terrain.send_report(chan);
        break;
#endif

    case MSG_WIND:
        CHECK_PAYLOAD_SIZE(WIND);
        send_wind();
        break;

    case MSG_ADSB_VEHICLE: {
#if HAL_ADSB_ENABLED
        CHECK_PAYLOAD_SIZE(ADSB_VEHICLE);
        copter.adsb.send_adsb_vehicle(chan);
#endif
#if AP_OAPATHPLANNER_ENABLED
        AP_OADatabase *oadb = AP_OADatabase::get_singleton();
        if (oadb != nullptr) {
            CHECK_PAYLOAD_SIZE(ADSB_VEHICLE);
            uint16_t interval_ms = 0;
            if (get_ap_message_interval(id, interval_ms)) {
                oadb->send_adsb_vehicle(chan, interval_ms);
            }
        }
#endif
        break;
    }

    default:
        return GCS_MAVLINK::try_send_message(id);
    }
    return true;
}


MISSION_STATE GCS_MAVLINK_Copter::mission_state(const class AP_Mission &mission) const
{
    if (copter.mode_auto.paused()) {
        return MISSION_STATE_PAUSED;
    }
    return GCS_MAVLINK::mission_state(mission);
}

bool GCS_MAVLINK_Copter::handle_guided_request(AP_Mission::Mission_Command &cmd)
{
#if MODE_AUTO_ENABLED
    return copter.mode_auto.do_guided(cmd);
#else
    return false;
#endif
}

void GCS_MAVLINK_Copter::packetReceived(const mavlink_status_t &status,
                                        const mavlink_message_t &msg)
{
    // we handle these messages here to avoid them being blocked by mavlink routing code
#if AP_ADSB_AVOIDANCE_ENABLED
    if (copter.g2.dev_options.get() & DevOptionADSBMAVLink) {
        // optional handling of GLOBAL_POSITION_INT as a MAVLink based avoidance source
        copter.avoidance_adsb.handle_msg(msg);
    }
#endif
#if defined(MAVLINK_MSG_ID_HQC_FINISH)
    if (msg.msgid == MAVLINK_MSG_ID_HQC_FINISH) {
        handle_hqc_finish(msg);
        return;
    }
#endif
#ifdef MAVLINK2
if (crypto_gate_open()) {
    const bool signed_v2 = (msg.incompat_flags & MAVLINK_IFLAG_SIGNED) != 0;
    if (!signed_v2 && !is_allowlisted_unsigned(msg.msgid)) {
        return; // drop
    }
}
#endif
    GCS_MAVLINK::packetReceived(status, msg);
}

bool GCS_MAVLINK_Copter::params_ready() const
{
    if (AP_BoardConfig::in_config_error()) {
        // we may never have parameters "initialised" in this case
        return true;
    }
    // if we have not yet initialised (including allocating the motors
    // object) we drop this request. That prevents the GCS from getting
    // a confusing parameter count during bootup
    return copter.ap.initialised_params;
}

void GCS_MAVLINK_Copter::send_banner()
{
    GCS_MAVLINK::send_banner();
    if (copter.motors == nullptr) {
        send_text(MAV_SEVERITY_INFO, "motors not allocated");
        return;
    }
    char frame_and_type_string[30];
    copter.motors->get_frame_and_type_string(frame_and_type_string, ARRAY_SIZE(frame_and_type_string));
    send_text(MAV_SEVERITY_INFO, "%s", frame_and_type_string);
}

void GCS_MAVLINK_Copter::handle_command_ack(const mavlink_message_t &msg)
{
    copter.command_ack_counter++;
    GCS_MAVLINK::handle_command_ack(msg);
}

/*
  handle a LANDING_TARGET command. The timestamp has been jitter corrected
*/
void GCS_MAVLINK_Copter::handle_landing_target(const mavlink_landing_target_t &packet, uint32_t timestamp_ms)
{
#if AC_PRECLAND_ENABLED
    copter.precland.handle_msg(packet, timestamp_ms);
#endif
}

MAV_RESULT GCS_MAVLINK_Copter::_handle_command_preflight_calibration(const mavlink_command_int_t &packet, const mavlink_message_t &msg)
{
    if (packet.y == 1) {
        // compassmot calibration
        return copter.mavlink_compassmot(*this);
    }

    return GCS_MAVLINK::_handle_command_preflight_calibration(packet, msg);
}


MAV_RESULT GCS_MAVLINK_Copter::handle_command_do_set_roi(const Location &roi_loc)
{
    if (!roi_loc.check_latlng()) {
        return MAV_RESULT_FAILED;
    }
    copter.flightmode->auto_yaw.set_roi(roi_loc);
    return MAV_RESULT_ACCEPTED;
}

MAV_RESULT GCS_MAVLINK_Copter::handle_preflight_reboot(const mavlink_command_int_t &packet, const mavlink_message_t &msg)
{
    // reject reboot if user has also specified they want the "Auto" ESC calibration on next reboot
    if (copter.g.esc_calibrate == (uint8_t)Copter::ESCCalibrationModes::ESCCAL_AUTO) {
        send_text(MAV_SEVERITY_CRITICAL, "Reboot rejected, ESC cal on reboot");
        return MAV_RESULT_FAILED;
    }

    // call parent
    return GCS_MAVLINK::handle_preflight_reboot(packet, msg);
}

MAV_RESULT GCS_MAVLINK_Copter::handle_command_int_do_reposition(const mavlink_command_int_t &packet)
{
#if MODE_GUIDED_ENABLED
    const bool change_modes = ((int32_t)packet.param2 & MAV_DO_REPOSITION_FLAGS_CHANGE_MODE) == MAV_DO_REPOSITION_FLAGS_CHANGE_MODE;
    if (!copter.flightmode->in_guided_mode() && !change_modes) {
        return MAV_RESULT_DENIED;
    }

    // sanity check location
    if (!check_latlng(packet.x, packet.y)) {
        return MAV_RESULT_DENIED;
    }

    Location request_location;
    if (!location_from_command_t(packet, request_location)) {
        return MAV_RESULT_DENIED;
    }

    if (request_location.sanitize(copter.current_loc)) {
        // if the location wasn't already sane don't load it
        return MAV_RESULT_DENIED; // failed as the location is not valid
    }

    // we need to do this first, as we don't want to change the flight mode unless we can also set the target
    if (!copter.mode_guided.set_destination(request_location, false, 0, false, 0)) {
        return MAV_RESULT_FAILED;
    }

    if (!copter.flightmode->in_guided_mode()) {
        if (!copter.set_mode(Mode::Number::GUIDED, ModeReason::GCS_COMMAND)) {
            return MAV_RESULT_FAILED;
        }
        // the position won't have been loaded if we had to change the flight mode, so load it again
        if (!copter.mode_guided.set_destination(request_location, false, 0, false, 0)) {
            return MAV_RESULT_FAILED;
        }
    }

    return MAV_RESULT_ACCEPTED;
#else
    return MAV_RESULT_UNSUPPORTED;
#endif
}

MAV_RESULT GCS_MAVLINK_Copter::handle_command_int_packet(const mavlink_command_int_t &packet, const mavlink_message_t &msg)
{
    switch(packet.command) {

    case MAV_CMD_CONDITION_YAW:
        return handle_MAV_CMD_CONDITION_YAW(packet);

    case MAV_CMD_DO_CHANGE_SPEED:
        return handle_MAV_CMD_DO_CHANGE_SPEED(packet);

    case MAV_CMD_DO_REPOSITION:
        return handle_command_int_do_reposition(packet);

    // pause or resume an auto mission
    case MAV_CMD_DO_PAUSE_CONTINUE:
        return handle_command_pause_continue(packet);

    case MAV_CMD_DO_MOTOR_TEST:
        return handle_MAV_CMD_DO_MOTOR_TEST(packet);

    case MAV_CMD_NAV_TAKEOFF:
    case MAV_CMD_NAV_VTOL_TAKEOFF:
        return handle_MAV_CMD_NAV_TAKEOFF(packet);

#if HAL_PARACHUTE_ENABLED
    case MAV_CMD_DO_PARACHUTE:
        return handle_MAV_CMD_DO_PARACHUTE(packet);
#endif

#if AC_MAVLINK_SOLO_BUTTON_COMMAND_HANDLING_ENABLED
    // Solo user presses pause button
    case MAV_CMD_SOLO_BTN_PAUSE_CLICK:
        return handle_MAV_CMD_SOLO_BTN_PAUSE_CLICK(packet);
    // Solo user presses Fly button:
    case MAV_CMD_SOLO_BTN_FLY_HOLD:
        return handle_MAV_CMD_SOLO_BTN_FLY_HOLD(packet);
    // Solo user holds down Fly button for a couple of seconds
    case MAV_CMD_SOLO_BTN_FLY_CLICK:
        return handle_MAV_CMD_SOLO_BTN_FLY_CLICK(packet);
#endif

#if MODE_AUTO_ENABLED
    case MAV_CMD_MISSION_START:
        return handle_MAV_CMD_MISSION_START(packet);
#endif

#if AP_WINCH_ENABLED
    case MAV_CMD_DO_WINCH:
        return handle_MAV_CMD_DO_WINCH(packet);
#endif

    case MAV_CMD_NAV_LOITER_UNLIM:
        if (!copter.set_mode(Mode::Number::LOITER, ModeReason::GCS_COMMAND)) {
            return MAV_RESULT_FAILED;
        }
        return MAV_RESULT_ACCEPTED;

    case MAV_CMD_NAV_RETURN_TO_LAUNCH:
        if (!copter.set_mode(Mode::Number::RTL, ModeReason::GCS_COMMAND)) {
            return MAV_RESULT_FAILED;
        }
        return MAV_RESULT_ACCEPTED;

    case MAV_CMD_NAV_VTOL_LAND:
    case MAV_CMD_NAV_LAND:
        if (!copter.set_mode(Mode::Number::LAND, ModeReason::GCS_COMMAND)) {
            return MAV_RESULT_FAILED;
        }
        return MAV_RESULT_ACCEPTED;

#if MODE_AUTO_ENABLED
    case MAV_CMD_DO_RETURN_PATH_START:
        if (copter.mode_auto.return_path_start_auto_RTL(ModeReason::GCS_COMMAND)) {
            return MAV_RESULT_ACCEPTED;
        }
        return MAV_RESULT_FAILED;

    case MAV_CMD_DO_LAND_START:
        if (copter.mode_auto.jump_to_landing_sequence_auto_RTL(ModeReason::GCS_COMMAND)) {
            return MAV_RESULT_ACCEPTED;
        }
        return MAV_RESULT_FAILED;
#endif

    default:
        return GCS_MAVLINK::handle_command_int_packet(packet, msg);
    }
}

#if HAL_MOUNT_ENABLED
MAV_RESULT GCS_MAVLINK_Copter::handle_command_mount(const mavlink_command_int_t &packet, const mavlink_message_t &msg)
{
    switch (packet.command) {
    case MAV_CMD_DO_MOUNT_CONTROL:
        // if vehicle has a camera mount but it doesn't do pan control then yaw the entire vehicle instead
        if (((MAV_MOUNT_MODE)packet.z == MAV_MOUNT_MODE_MAVLINK_TARGETING) &&
            (copter.camera_mount.get_mount_type() != AP_Mount::Type::None) &&
            !copter.camera_mount.has_pan_control()) {
            // Per the handler in AP_Mount, DO_MOUNT_CONTROL yaw angle is in body frame, which is
            // equivalent to an offset to the current yaw demand.
            copter.flightmode->auto_yaw.set_yaw_angle_offset_deg(packet.param3);
        }
        break;
    default:
        break;
    }
    return GCS_MAVLINK::handle_command_mount(packet, msg);
}
#endif

MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_NAV_TAKEOFF(const mavlink_command_int_t &packet)
{
    if (packet.frame != MAV_FRAME_GLOBAL_RELATIVE_ALT) {
        return MAV_RESULT_DENIED;  // meaning some parameters are bad
    }

        // param3 : horizontal navigation by pilot acceptable
        // param4 : yaw angle   (not supported)
        // param5 : latitude    (not supported)
        // param6 : longitude   (not supported)
        // param7 : altitude [metres]

        float takeoff_alt_m = packet.z;

        if (!copter.flightmode->do_user_takeoff_U_m(takeoff_alt_m, is_zero(packet.param3))) {
            return MAV_RESULT_FAILED;
        }
        return MAV_RESULT_ACCEPTED;
}

#if AP_MAVLINK_COMMAND_LONG_ENABLED
bool GCS_MAVLINK_Copter::mav_frame_for_command_long(MAV_FRAME &frame, MAV_CMD packet_command) const
{
    if (packet_command == MAV_CMD_NAV_TAKEOFF ||
        packet_command == MAV_CMD_NAV_VTOL_TAKEOFF) {
        frame = MAV_FRAME_GLOBAL_RELATIVE_ALT;
        return true;
    }
    return GCS_MAVLINK::mav_frame_for_command_long(frame, packet_command);
}
#endif


MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_CONDITION_YAW(const mavlink_command_int_t &packet)
{
        // param1 : target angle [0-360]
        // param2 : speed during change [deg per second]
        // param3 : direction (-1:ccw, +1:cw)
        // param4 : relative offset (1) or absolute angle (0)
        if ((packet.param1 >= 0.0f)   &&
            (packet.param1 <= 360.0f) &&
            (is_zero(packet.param4) || is_equal(packet.param4,1.0f))) {
            copter.flightmode->auto_yaw.set_fixed_yaw_rad(
                radians(packet.param1),
                radians(packet.param2),
                (int8_t)packet.param3,
                is_positive(packet.param4));
            return MAV_RESULT_ACCEPTED;
        }
        return MAV_RESULT_FAILED;
}

MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_DO_CHANGE_SPEED(const mavlink_command_int_t &packet)
{
    if (!is_positive(packet.param2)) {
        // Target speed must be larger than zero
        return MAV_RESULT_DENIED;
    }

    const float speed_ms = packet.param2;

    bool success = false;
    switch (SPEED_TYPE(packet.param1)) {
        case SPEED_TYPE_ENUM_END:
            return MAV_RESULT_DENIED;

        case SPEED_TYPE_AIRSPEED: // Airspeed is treated as ground speed for GCS compatibility
        case SPEED_TYPE_GROUNDSPEED:
            success = copter.flightmode->set_speed_NE_ms(speed_ms);
            break;

        case SPEED_TYPE_CLIMB_SPEED:
            success = copter.flightmode->set_speed_up_ms(speed_ms);
            break;

        case SPEED_TYPE_DESCENT_SPEED:
            success = copter.flightmode->set_speed_down_ms(speed_ms);
            break;
    }

    return success ? MAV_RESULT_ACCEPTED : MAV_RESULT_FAILED;
}

#if MODE_AUTO_ENABLED
MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_MISSION_START(const mavlink_command_int_t &packet)
{
        if (!is_zero(packet.param1) || !is_zero(packet.param2)) {
            // first-item/last item not supported
            return MAV_RESULT_DENIED;
        }
        if (copter.set_mode(Mode::Number::AUTO, ModeReason::GCS_COMMAND)) {
            copter.set_auto_armed(true);
            if (copter.mode_auto.mission.state() != AP_Mission::MISSION_RUNNING) {
                copter.mode_auto.mission.start_or_resume();
            }
            return MAV_RESULT_ACCEPTED;
        }
        return MAV_RESULT_FAILED;
}
#endif



#if HAL_PARACHUTE_ENABLED
MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_DO_PARACHUTE(const mavlink_command_int_t &packet)
{
        // configure or release parachute
        switch ((uint16_t)packet.param1) {
        case PARACHUTE_DISABLE:
            copter.parachute.enabled(false);
            return MAV_RESULT_ACCEPTED;
        case PARACHUTE_ENABLE:
            copter.parachute.enabled(true);
            return MAV_RESULT_ACCEPTED;
        case PARACHUTE_RELEASE:
            // treat as a manual release which performs some additional check of altitude
            copter.parachute_manual_release();
            return MAV_RESULT_ACCEPTED;
        }
        return MAV_RESULT_FAILED;
}
#endif

MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_DO_MOTOR_TEST(const mavlink_command_int_t &packet)
{
        // param1 : motor sequence number (a number from 1 to max number of motors on the vehicle)
        // param2 : throttle type (0=throttle percentage, 1=PWM, 2=pilot throttle channel pass-through. See MOTOR_TEST_THROTTLE_TYPE enum)
        // param3 : throttle (range depends upon param2)
        // param4 : timeout (in seconds)
        // param5 : num_motors (in sequence)
        // param6 : motor test order
        return copter.mavlink_motor_test_start(*this,
                                               (uint8_t)packet.param1,
                                               (uint8_t)packet.param2,
                                               packet.param3,
                                               packet.param4,
                                               (uint8_t)packet.x);
}

#if AP_WINCH_ENABLED
MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_DO_WINCH(const mavlink_command_int_t &packet)
{
        // param1 : winch number (ignored)
        // param2 : action (0=relax, 1=relative length control, 2=rate control). See WINCH_ACTIONS enum.
        if (!copter.g2.winch.enabled()) {
            return MAV_RESULT_FAILED;
        }
        switch ((uint8_t)packet.param2) {
        case WINCH_RELAXED:
            copter.g2.winch.relax();
            return MAV_RESULT_ACCEPTED;
        case WINCH_RELATIVE_LENGTH_CONTROL: {
            copter.g2.winch.release_length(packet.param3);
            return MAV_RESULT_ACCEPTED;
        }
        case WINCH_RATE_CONTROL:
            copter.g2.winch.set_desired_rate(packet.param4);
            return MAV_RESULT_ACCEPTED;
        default:
            break;
        }
        return MAV_RESULT_FAILED;
}
#endif  // AP_WINCH_ENABLED

#if AC_MAVLINK_SOLO_BUTTON_COMMAND_HANDLING_ENABLED
MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_SOLO_BTN_FLY_CLICK(const mavlink_command_int_t &packet)
{
        if (copter.failsafe.radio) {
            return MAV_RESULT_ACCEPTED;
        }

        // set mode to Loiter or fall back to AltHold
        if (!copter.set_mode(Mode::Number::LOITER, ModeReason::GCS_COMMAND)) {
            copter.set_mode(Mode::Number::ALT_HOLD, ModeReason::GCS_COMMAND);
        }
        return MAV_RESULT_ACCEPTED;
}

MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_SOLO_BTN_FLY_HOLD(const mavlink_command_int_t &packet)
{
        if (copter.failsafe.radio) {
            return MAV_RESULT_ACCEPTED;
        }

        if (!copter.motors->armed()) {
            // if disarmed, arm motors
            copter.arming.arm(AP_Arming::Method::MAVLINK);
        } else if (copter.ap.land_complete) {
            // if armed and landed, takeoff
            if (copter.set_mode(Mode::Number::LOITER, ModeReason::GCS_COMMAND)) {
                copter.flightmode->do_user_takeoff_U_m(packet.param1, true);
            }
        } else {
            // if flying, land
            copter.set_mode(Mode::Number::LAND, ModeReason::GCS_COMMAND);
        }
        return MAV_RESULT_ACCEPTED;
}

MAV_RESULT GCS_MAVLINK_Copter::handle_MAV_CMD_SOLO_BTN_PAUSE_CLICK(const mavlink_command_int_t &packet)
{
        if (copter.failsafe.radio) {
            return MAV_RESULT_ACCEPTED;
        }

        if (copter.motors->armed()) {
            if (copter.ap.land_complete) {
                // if landed, disarm motors
                copter.arming.disarm(AP_Arming::Method::SOLOPAUSEWHENLANDED);
            } else {
                // assume that shots modes are all done in guided.
                // NOTE: this may need to change if we add a non-guided shot mode
                bool shot_mode = (!is_zero(packet.param1) && (copter.flightmode->mode_number() == Mode::Number::GUIDED || copter.flightmode->mode_number() == Mode::Number::GUIDED_NOGPS));

                if (!shot_mode) {
#if MODE_BRAKE_ENABLED
                    if (copter.set_mode(Mode::Number::BRAKE, ModeReason::GCS_COMMAND)) {
                        copter.mode_brake.timeout_to_loiter_ms(2500);
                    } else {
                        copter.set_mode(Mode::Number::ALT_HOLD, ModeReason::GCS_COMMAND);
                    }
#else
                    copter.set_mode(Mode::Number::ALT_HOLD, ModeReason::GCS_COMMAND);
#endif
                } else {
                    // SoloLink is expected to handle pause in shots
                }
            }
        }
        return MAV_RESULT_ACCEPTED;
}
#endif  // AC_MAVLINK_SOLO_BUTTON_COMMAND_HANDLING_ENABLED

MAV_RESULT GCS_MAVLINK_Copter::handle_command_pause_continue(const mavlink_command_int_t &packet)
{
    // requested pause
    if ((uint8_t) packet.param1 == 0) {
        if (copter.flightmode->pause()) {
            return MAV_RESULT_ACCEPTED;
        }
        send_text(MAV_SEVERITY_INFO, "Failed to pause");
        return MAV_RESULT_FAILED;
    }

    // requested resume
    if ((uint8_t) packet.param1 == 1) {
        if (copter.flightmode->resume()) {
            return MAV_RESULT_ACCEPTED;
        }
        send_text(MAV_SEVERITY_INFO, "Failed to resume");
        return MAV_RESULT_FAILED;
    }
    return MAV_RESULT_DENIED;
}

#if HAL_MOUNT_ENABLED
void GCS_MAVLINK_Copter::handle_mount_message(const mavlink_message_t &msg)
{
    switch (msg.msgid) {
    case MAVLINK_MSG_ID_MOUNT_CONTROL:
        // if vehicle has a camera mount but it doesn't do pan control then yaw the entire vehicle instead
        if ((copter.camera_mount.get_mount_type() != AP_Mount::Type::None) &&
            (copter.camera_mount.get_mode() == MAV_MOUNT_MODE_MAVLINK_TARGETING) &&
            !copter.camera_mount.has_pan_control()) {
            // Per the handler in AP_Mount, MOUNT_CONTROL yaw angle is in body frame, which is
            // equivalent to an offset to the current yaw demand.
            const float yaw_offset_deg = mavlink_msg_mount_control_get_input_c(&msg) * 0.01f;
            copter.flightmode->auto_yaw.set_yaw_angle_offset_deg(yaw_offset_deg);
            break;
        }
    }
    GCS_MAVLINK::handle_mount_message(msg);
}
#endif

// this is called on receipt of a MANUAL_CONTROL packet and is
// expected to call manual_override to override RC input on desired
// axes.
void GCS_MAVLINK_Copter::handle_manual_control_axes(const mavlink_manual_control_t &packet, const uint32_t tnow)
{
    if (packet.z < 0) { // Copter doesn't do negative thrust
        return;
    }

    manual_override(copter.channel_roll, packet.y, 1000, 2000, tnow);
    manual_override(copter.channel_pitch, packet.x, 1000, 2000, tnow, true);
    manual_override(copter.channel_throttle, packet.z, 0, 1000, tnow);
    manual_override(copter.channel_yaw, packet.r, 1000, 2000, tnow);
}

// sanity check velocity or acceleration vector components are numbers
// (e.g. not NaN) and below 1000. vec argument units are in meters/second or
// metres/second/second
bool GCS_MAVLINK_Copter::sane_vel_or_acc_vector(const Vector3f &vec) const
{
    for (uint8_t i=0; i<3; i++) {
        // consider velocity invalid if any component nan or >1000(m/s or m/s/s)
        if (isnan(vec[i]) || fabsf(vec[i]) > 1000) {
            return false;
        }
    }
    return true;
}

#if MODE_GUIDED_ENABLED
    // for mavlink SET_POSITION_TARGET messages
    constexpr uint32_t MAVLINK_SET_POS_TYPE_MASK_POS_IGNORE =
        POSITION_TARGET_TYPEMASK_X_IGNORE |
        POSITION_TARGET_TYPEMASK_Y_IGNORE |
        POSITION_TARGET_TYPEMASK_Z_IGNORE;

    constexpr uint32_t MAVLINK_SET_POS_TYPE_MASK_VEL_IGNORE =
        POSITION_TARGET_TYPEMASK_VX_IGNORE |
        POSITION_TARGET_TYPEMASK_VY_IGNORE |
        POSITION_TARGET_TYPEMASK_VZ_IGNORE;

    constexpr uint32_t MAVLINK_SET_POS_TYPE_MASK_ACC_IGNORE =
        POSITION_TARGET_TYPEMASK_AX_IGNORE |
        POSITION_TARGET_TYPEMASK_AY_IGNORE |
        POSITION_TARGET_TYPEMASK_AZ_IGNORE;

    constexpr uint32_t MAVLINK_SET_POS_TYPE_MASK_YAW_IGNORE =
        POSITION_TARGET_TYPEMASK_YAW_IGNORE;
    constexpr uint32_t MAVLINK_SET_POS_TYPE_MASK_YAW_RATE_IGNORE =
        POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE;
    constexpr uint32_t MAVLINK_SET_POS_TYPE_MASK_FORCE_SET =
        POSITION_TARGET_TYPEMASK_FORCE_SET;
#endif

#if MODE_GUIDED_ENABLED
void GCS_MAVLINK_Copter::handle_message_set_attitude_target(const mavlink_message_t &msg)
{
    // decode packet
    mavlink_set_attitude_target_t packet;
    mavlink_msg_set_attitude_target_decode(&msg, &packet);

    // exit if vehicle is not in Guided mode or Auto-Guided mode
    if (!copter.flightmode->in_guided_mode()) {
        return;
    }

    const bool roll_rate_ignore   = packet.type_mask & ATTITUDE_TARGET_TYPEMASK_BODY_ROLL_RATE_IGNORE;
    const bool pitch_rate_ignore  = packet.type_mask & ATTITUDE_TARGET_TYPEMASK_BODY_PITCH_RATE_IGNORE;
    const bool yaw_rate_ignore    = packet.type_mask & ATTITUDE_TARGET_TYPEMASK_BODY_YAW_RATE_IGNORE;
    const bool throttle_ignore    = packet.type_mask & ATTITUDE_TARGET_TYPEMASK_THROTTLE_IGNORE;
    const bool attitude_ignore    = packet.type_mask & ATTITUDE_TARGET_TYPEMASK_ATTITUDE_IGNORE;

    // ensure thrust field is not ignored
    if (throttle_ignore) {
        // The throttle input is not defined
        copter.mode_guided.init(true);
        return;
    }

    Quaternion attitude_quat;
    if (attitude_ignore) {
        attitude_quat.zero();
    } else {
        attitude_quat = Quaternion(packet.q[0],packet.q[1],packet.q[2],packet.q[3]);

        // Do not accept the attitude_quaternion
        // if its magnitude is not close to unit length +/- 1E-3
        // this limit is somewhat greater than sqrt(FLT_EPSL)
        if (!attitude_quat.is_unit_length()) {
            // The attitude quaternion is ill-defined
            copter.mode_guided.init(true);
            return;
        }
    }

    Vector3f ang_vel_body;
    if (!roll_rate_ignore && !pitch_rate_ignore && !yaw_rate_ignore) {
        ang_vel_body.x = packet.body_roll_rate;
        ang_vel_body.y = packet.body_pitch_rate;
        ang_vel_body.z = packet.body_yaw_rate;
    } else if (!(roll_rate_ignore && pitch_rate_ignore && yaw_rate_ignore)) {
        // The body rates are ill-defined
        // input is not valid so stop
        copter.mode_guided.init(true);
        return;
    }

    // check if the message's thrust field should be interpreted as a climb rate or as thrust
    const bool use_thrust = copter.mode_guided.set_attitude_target_provides_thrust();

    float climb_rate_ms_or_thrust;
    if (use_thrust) {
        // interpret thrust as thrust
        climb_rate_ms_or_thrust = constrain_float(packet.thrust, -1.0f, 1.0f);
    } else {
        // convert thrust to climb rate
        packet.thrust = constrain_float(packet.thrust, 0.0f, 1.0f);
        if (is_equal(packet.thrust, 0.5f)) {
            climb_rate_ms_or_thrust = 0.0f;
        } else if (packet.thrust > 0.5f) {
            // climb at up to WPNAV_SPEED_UP
            climb_rate_ms_or_thrust = (packet.thrust - 0.5f) * 2.0f * copter.wp_nav->get_default_speed_up_ms();
        } else {
            // descend at up to WPNAV_SPEED_DN
            climb_rate_ms_or_thrust = (0.5f - packet.thrust) * 2.0f * -copter.wp_nav->get_default_speed_down_ms();
        }
    }

    copter.mode_guided.set_angle(attitude_quat, ang_vel_body,
            climb_rate_ms_or_thrust, use_thrust);
}

void GCS_MAVLINK_Copter::handle_message_set_position_target_local_ned(const mavlink_message_t &msg)
{
    // decode packet
    mavlink_set_position_target_local_ned_t packet;
    mavlink_msg_set_position_target_local_ned_decode(&msg, &packet);

    // exit if vehicle is not in Guided mode or Auto-Guided mode
    if (!copter.flightmode->in_guided_mode()) {
        return;
    }

    // check for supported coordinate frames
    if (packet.coordinate_frame != MAV_FRAME_LOCAL_NED &&
        packet.coordinate_frame != MAV_FRAME_LOCAL_OFFSET_NED &&
        packet.coordinate_frame != MAV_FRAME_BODY_NED &&
        packet.coordinate_frame != MAV_FRAME_BODY_OFFSET_NED) {
        // input is not valid so stop
        copter.mode_guided.init(true);
        return;
    }

    bool pos_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_POS_IGNORE;
    bool vel_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_VEL_IGNORE;
    bool acc_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_ACC_IGNORE;
    bool yaw_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_YAW_IGNORE;
    bool yaw_rate_ignore = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_YAW_RATE_IGNORE;
    bool force_set       = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_FORCE_SET;

    // Force inputs are not supported
    // Do not accept command if force_set is true and acc_ignore is false
    if (force_set && !acc_ignore) {
        copter.mode_guided.init(true);
        return;
    }

    // prepare position
    Vector3f pos_neu_m;
    if (!pos_ignore) {
        // convert to m
        pos_neu_m = Vector3f{packet.x, packet.y, -packet.z};
        // rotate to body-frame if necessary
        if (packet.coordinate_frame == MAV_FRAME_BODY_NED ||
            packet.coordinate_frame == MAV_FRAME_BODY_OFFSET_NED) {
            copter.rotate_body_frame_to_NE(pos_neu_m.x, pos_neu_m.y);
        }
        // add body offset if necessary
        if (packet.coordinate_frame == MAV_FRAME_LOCAL_OFFSET_NED ||
            packet.coordinate_frame == MAV_FRAME_BODY_NED ||
            packet.coordinate_frame == MAV_FRAME_BODY_OFFSET_NED) {
            Vector3f pos_ned_m;
            if (!AP::ahrs().get_relative_position_NED_origin_float(pos_ned_m)) {
                // need position estimate to calculate target position
                copter.mode_guided.init(true);
                return;
            }
            pos_neu_m.xy() += pos_ned_m.xy();
            pos_neu_m.z -= pos_ned_m.z;
        }
    }

    // prepare velocity
    Vector3f vel_neu_ms;
    if (!vel_ignore) {
        vel_neu_ms = Vector3f{packet.vx, packet.vy, -packet.vz};
        if (!sane_vel_or_acc_vector(vel_neu_ms)) {
            // input is not valid so stop
            copter.mode_guided.init(true);
            return;
        }
        // rotate to body-frame if necessary
        if (packet.coordinate_frame == MAV_FRAME_BODY_NED || packet.coordinate_frame == MAV_FRAME_BODY_OFFSET_NED) {
            copter.rotate_body_frame_to_NE(vel_neu_ms.x, vel_neu_ms.y);
        }
    }

    // prepare acceleration
    Vector3f accel_neu_mss;
    if (!acc_ignore) {
        accel_neu_mss = Vector3f{packet.afx, packet.afy, -packet.afz};
        // rotate to body-frame if necessary
        if (packet.coordinate_frame == MAV_FRAME_BODY_NED || packet.coordinate_frame == MAV_FRAME_BODY_OFFSET_NED) {
            copter.rotate_body_frame_to_NE(accel_neu_mss.x, accel_neu_mss.y);
        }
    }

    // prepare yaw
    float yaw_rad = 0.0f;
    bool yaw_relative = false;
    float yaw_rate_rads = 0.0f;
    if (!yaw_ignore) {
        yaw_rad = packet.yaw;
        yaw_relative = packet.coordinate_frame == MAV_FRAME_BODY_NED || packet.coordinate_frame == MAV_FRAME_BODY_OFFSET_NED;
    }
    if (!yaw_rate_ignore) {
        yaw_rate_rads = packet.yaw_rate;
    }

    // send request
    if (!pos_ignore && !vel_ignore) {
        copter.mode_guided.set_pos_vel_accel_NEU_m(pos_neu_m, vel_neu_ms, accel_neu_mss, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads, yaw_relative);
    } else if (pos_ignore && !vel_ignore) {
        copter.mode_guided.set_vel_accel_NEU_m(vel_neu_ms, accel_neu_mss, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads, yaw_relative);
    } else if (pos_ignore && vel_ignore && !acc_ignore) {
        copter.mode_guided.set_accel_NEU_mss(accel_neu_mss, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads, yaw_relative);
    } else if (!pos_ignore && vel_ignore && acc_ignore) {
        copter.mode_guided.set_pos_NEU_m(pos_neu_m, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads, yaw_relative, false);
    } else {
        // input is not valid so stop
        copter.mode_guided.init(true);
    }
}

void GCS_MAVLINK_Copter::handle_message_set_position_target_global_int(const mavlink_message_t &msg)
{
    // decode packet
    mavlink_set_position_target_global_int_t packet;
    mavlink_msg_set_position_target_global_int_decode(&msg, &packet);

    // exit if vehicle is not in Guided mode or Auto-Guided mode
    if (!copter.flightmode->in_guided_mode()) {
        return;
    }

    // todo: do we need to check for supported coordinate frames

    bool pos_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_POS_IGNORE;
    bool vel_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_VEL_IGNORE;
    bool acc_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_ACC_IGNORE;
    bool yaw_ignore      = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_YAW_IGNORE;
    bool yaw_rate_ignore = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_YAW_RATE_IGNORE;
    bool force_set       = packet.type_mask & MAVLINK_SET_POS_TYPE_MASK_FORCE_SET;

    // Force inputs are not supported
    // Do not accept command if force_set is true and acc_ignore is false
    if (force_set && !acc_ignore) {
        copter.mode_guided.init(true);
        return;
    }

    // extract location from message
    Location loc;
    if (!pos_ignore) {
        // sanity check location
        if (!check_latlng(packet.lat_int, packet.lon_int)) {
            // input is not valid so stop
            copter.mode_guided.init(true);
            return;
        }
        Location::AltFrame frame;
        if (!mavlink_coordinate_frame_to_location_alt_frame((MAV_FRAME)packet.coordinate_frame, frame)) {
            // unknown coordinate frame
            // input is not valid so stop
            copter.mode_guided.init(true);
            return;
        }
        loc = {packet.lat_int, packet.lon_int, int32_t(packet.alt*100), frame};
    }

    // prepare velocity
    Vector3f vel_neu_ms;
    if (!vel_ignore) {
        vel_neu_ms = Vector3f{packet.vx, packet.vy, -packet.vz};
        if (!sane_vel_or_acc_vector(vel_neu_ms)) {
            // input is not valid so stop
            copter.mode_guided.init(true);
            return;
        }
    }

    // prepare acceleration
    Vector3f accel_neu_mss;
    if (!acc_ignore) {
        accel_neu_mss = Vector3f{packet.afx, packet.afy, -packet.afz};
    }

    // prepare yaw
    float yaw_rad = 0.0f;
    float yaw_rate_rads = 0.0f;
    if (!yaw_ignore) {
        yaw_rad = packet.yaw;
    }
    if (!yaw_rate_ignore) {
        yaw_rate_rads = packet.yaw_rate;
    }

    // send targets to the appropriate guided mode controller
    if (!pos_ignore && !vel_ignore) {
        // convert Location to vector from ekf origin for posvel controller
        if (loc.get_alt_frame() == Location::AltFrame::ABOVE_TERRAIN) {
            // posvel controller does not support alt-above-terrain
            // input is not valid so stop
            copter.mode_guided.init(true);
            return;
        }
        Vector3f pos_neu_m;
        if (!loc.get_vector_from_origin_NEU_m(pos_neu_m)) {
            // input is not valid so stop
            copter.mode_guided.init(true);
            return;
        }
        copter.mode_guided.set_pos_vel_NEU_m(pos_neu_m, vel_neu_ms, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads);
    } else if (pos_ignore && !vel_ignore) {
        copter.mode_guided.set_vel_accel_NEU_m(vel_neu_ms, accel_neu_mss, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads);
    } else if (pos_ignore && vel_ignore && !acc_ignore) {
        copter.mode_guided.set_accel_NEU_mss(accel_neu_mss, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads);
    } else if (!pos_ignore && vel_ignore && acc_ignore) {
        copter.mode_guided.set_destination(loc, !yaw_ignore, yaw_rad, !yaw_rate_ignore, yaw_rate_rads);
    } else {
        // input is not valid so stop
        copter.mode_guided.init(true);
    }
}
#endif  // MODE_GUIDED_ENABLED

void GCS_MAVLINK_Copter::handle_message(const mavlink_message_t &msg)
{

    switch (msg.msgid) {
#if MODE_GUIDED_ENABLED
    case MAVLINK_MSG_ID_SET_ATTITUDE_TARGET:
        handle_message_set_attitude_target(msg);
        break;
    case MAVLINK_MSG_ID_SET_POSITION_TARGET_LOCAL_NED:
        handle_message_set_position_target_local_ned(msg);
        break;
    case MAVLINK_MSG_ID_SET_POSITION_TARGET_GLOBAL_INT:
        handle_message_set_position_target_global_int(msg);
        break;
#endif
#if AP_TERRAIN_AVAILABLE
    case MAVLINK_MSG_ID_TERRAIN_DATA:
    case MAVLINK_MSG_ID_TERRAIN_CHECK:
        copter.terrain.handle_data(chan, msg);
        break;
#endif
#if TOY_MODE_ENABLED
    case MAVLINK_MSG_ID_NAMED_VALUE_INT:
        copter.g2.toy_mode.handle_message(msg);
        break;
#endif
#if defined(MAVLINK_MSG_ID_HQC_HELLO)
    case MAVLINK_MSG_ID_CRYPTO_PKT:
        handle_crypto_pkt(msg);
        return;
    case MAVLINK_MSG_ID_HQC_HELLO:
        handle_hqc_hello(msg);
        return;
    case MAVLINK_MSG_ID_HQC_PK_CHUNK:
        handle_hqc_pk_chunk(msg);
        return;

    case MAVLINK_MSG_ID_HQC_CT_ACK:
        handle_hqc_ct_ack(msg);
        return;

    case MAVLINK_MSG_ID_HQC_FINISH:
        send_text(MAV_SEVERITY_INFO,
              "HQC_FINISH recv");
        handle_hqc_finish(msg);
        return;
#endif
    default:
        GCS_MAVLINK::handle_message(msg);
        break;
    }
}

MAV_RESULT GCS_MAVLINK_Copter::handle_flight_termination(const mavlink_command_int_t &packet) {
#if AP_COPTER_ADVANCED_FAILSAFE_ENABLED
    if (GCS_MAVLINK::handle_flight_termination(packet) == MAV_RESULT_ACCEPTED) {
        return MAV_RESULT_ACCEPTED;
    }
#endif
    if (packet.param1 > 0.5f) {
        copter.arming.disarm(AP_Arming::Method::TERMINATION);
        return MAV_RESULT_ACCEPTED;
    }

    return MAV_RESULT_FAILED;
}

float GCS_MAVLINK_Copter::vfr_hud_alt() const
{
    if (copter.g2.dev_options.get() & DevOptionVFR_HUDRelativeAlt) {
        // compatibility option for older mavlink-aware devices that
        // assume Copter returns a relative altitude in VFR_HUD.alt
        return copter.current_loc.alt * 0.01f;
    }
    return GCS_MAVLINK::vfr_hud_alt();
}

uint64_t GCS_MAVLINK_Copter::capabilities() const
{
    return (MAV_PROTOCOL_CAPABILITY_MISSION_FLOAT |
            MAV_PROTOCOL_CAPABILITY_MISSION_INT |
            MAV_PROTOCOL_CAPABILITY_COMMAND_INT |
            MAV_PROTOCOL_CAPABILITY_SET_POSITION_TARGET_LOCAL_NED |
            MAV_PROTOCOL_CAPABILITY_SET_POSITION_TARGET_GLOBAL_INT |
            MAV_PROTOCOL_CAPABILITY_FLIGHT_TERMINATION |
            MAV_PROTOCOL_CAPABILITY_SET_ATTITUDE_TARGET |
#if AP_TERRAIN_AVAILABLE
            (copter.terrain.enabled() ? MAV_PROTOCOL_CAPABILITY_TERRAIN : 0) |
#endif
            GCS_MAVLINK::capabilities());
}

MAV_LANDED_STATE GCS_MAVLINK_Copter::landed_state() const
{
    if (copter.ap.land_complete) {
        return MAV_LANDED_STATE_ON_GROUND;
    }
    if (copter.flightmode->is_landing()) {
        return MAV_LANDED_STATE_LANDING;
    }
    if (copter.flightmode->is_taking_off()) {
        return MAV_LANDED_STATE_TAKEOFF;
    }
    return MAV_LANDED_STATE_IN_AIR;
}

void GCS_MAVLINK_Copter::send_wind() const
{
    Vector3f airspeed_vec_bf;
    if (!AP::ahrs().airspeed_vector_true(airspeed_vec_bf)) {
        // if we don't have an airspeed estimate then we don't have a
        // valid wind estimate on copters
        return;
    }
    const Vector3f wind = AP::ahrs().wind_estimate();
    mavlink_msg_wind_send(
        chan,
        degrees(atan2f(-wind.y, -wind.x)),
        wind.length(),
        wind.z);
}

#if HAL_HIGH_LATENCY2_ENABLED
int16_t GCS_MAVLINK_Copter::high_latency_target_altitude() const
{
    AP_AHRS &ahrs = AP::ahrs();
    Location global_position_current;
    UNUSED_RESULT(ahrs.get_location(global_position_current));

    //return units are m
    if (copter.ap.initialised) {
        return global_position_current.alt * 0.01 + copter.pos_control->get_pos_error_U_m();
    }
    return 0;
    
}

uint8_t GCS_MAVLINK_Copter::high_latency_tgt_heading() const
{
    if (copter.ap.initialised) {
        // return units are deg/2
        const Mode *flightmode = copter.flightmode;
        // need to convert -180->180 to 0->360/2
        return wrap_360(flightmode->wp_bearing_deg()) * 0.5;
    }
    return 0;     
}
    
uint16_t GCS_MAVLINK_Copter::high_latency_tgt_dist() const
{
    if (copter.ap.initialised) {
        // return units are dm
        const Mode *flightmode = copter.flightmode;
        return MIN(flightmode->wp_distance_m(), UINT16_MAX) / 10;
    }
    return 0;
}

uint8_t GCS_MAVLINK_Copter::high_latency_tgt_airspeed() const
{
    if (copter.ap.initialised) {
        // return units are m/s*5
        return MIN(copter.pos_control->get_vel_target_NEU_ms().length() * 5.0, UINT8_MAX);
    }
    return 0;  
}

uint8_t GCS_MAVLINK_Copter::high_latency_wind_speed() const
{
    Vector3f airspeed_vec_bf;
    Vector3f wind;
    // return units are m/s*5
    if (AP::ahrs().airspeed_vector_true(airspeed_vec_bf)) {
        wind = AP::ahrs().wind_estimate();
        return wind.length() * 5;
    }
    return 0; 
}

uint8_t GCS_MAVLINK_Copter::high_latency_wind_direction() const
{
    Vector3f airspeed_vec_bf;
    Vector3f wind;
    // return units are deg/2
    if (AP::ahrs().airspeed_vector_true(airspeed_vec_bf)) {
        wind = AP::ahrs().wind_estimate();
        // need to convert -180->180 to 0->360/2
        return wrap_360(degrees(atan2f(-wind.y, -wind.x))) / 2;
    }
    return 0;
}
#endif // HAL_HIGH_LATENCY2_ENABLED

// Send the mode with the given index (not mode number!) return the total number of modes
// Index starts at 1
uint8_t GCS_MAVLINK_Copter::send_available_mode(uint8_t index) const
{
    const Mode* modes[] {
#if MODE_AUTO_ENABLED
        &copter.mode_auto, // This auto is actually auto RTL!
        &copter.mode_auto, // This one is really is auto!
#endif
#if MODE_ACRO_ENABLED
        &copter.mode_acro,
#endif
        &copter.mode_stabilize,
        &copter.mode_althold,
#if MODE_CIRCLE_ENABLED
        &copter.mode_circle,
#endif
#if MODE_LOITER_ENABLED
        &copter.mode_loiter,
#endif
#if MODE_GUIDED_ENABLED
        &copter.mode_guided,
#endif
        &copter.mode_land,
#if MODE_RTL_ENABLED
        &copter.mode_rtl,
#endif
#if MODE_DRIFT_ENABLED
        &copter.mode_drift,
#endif
#if MODE_SPORT_ENABLED
        &copter.mode_sport,
#endif
#if MODE_FLIP_ENABLED
        &copter.mode_flip,
#endif
#if AUTOTUNE_ENABLED
        &copter.mode_autotune,
#endif
#if MODE_POSHOLD_ENABLED
        &copter.mode_poshold,
#endif
#if MODE_BRAKE_ENABLED
        &copter.mode_brake,
#endif
#if MODE_THROW_ENABLED
        &copter.mode_throw,
#endif
#if AP_ADSB_AVOIDANCE_ENABLED
        &copter.mode_avoid_adsb,
#endif
#if MODE_GUIDED_NOGPS_ENABLED
        &copter.mode_guided_nogps,
#endif
#if MODE_SMARTRTL_ENABLED
        &copter.mode_smartrtl,
#endif
#if MODE_FLOWHOLD_ENABLED
        (Mode*)copter.g2.mode_flowhold_ptr,
#endif
#if MODE_FOLLOW_ENABLED
        &copter.mode_follow,
#endif
#if MODE_ZIGZAG_ENABLED
        &copter.mode_zigzag,
#endif
#if MODE_SYSTEMID_ENABLED
        (Mode *)copter.g2.mode_systemid_ptr,
#endif
#if MODE_AUTOROTATE_ENABLED
        &copter.mode_autorotate,
#endif
#if MODE_TURTLE_ENABLED
        &copter.mode_turtle,
#endif
    };

    const uint8_t base_mode_count = ARRAY_SIZE(modes);
    uint8_t mode_count = base_mode_count;

#if AP_SCRIPTING_ENABLED
    for (uint8_t i = 0; i < ARRAY_SIZE(copter.mode_guided_custom); i++) {
        if (copter.mode_guided_custom[i] != nullptr) {
            mode_count += 1;
        }
    }
#endif

    // Convert to zero indexed
    const uint8_t index_zero = index - 1;
    if (index_zero >= mode_count) {
        // Mode does not exist!?
        return mode_count;
    }

    // Ask the mode for its name and number
    const char* name;
    uint8_t mode_number;

    if (index_zero < base_mode_count) {
        name = modes[index_zero]->name();
        mode_number = (uint8_t)modes[index_zero]->mode_number();

    } else {
#if AP_SCRIPTING_ENABLED
        const uint8_t custom_index = index_zero - base_mode_count;
        if (copter.mode_guided_custom[custom_index] == nullptr) {
            // Invalid index, should not happen
            return mode_count;
        }
        name = copter.mode_guided_custom[custom_index]->name();
        mode_number = (uint8_t)copter.mode_guided_custom[custom_index]->mode_number();
#else
        // Should not endup here
        return mode_count;
#endif
    }

#if MODE_AUTO_ENABLED
    // Auto RTL is odd
    // Have to deal with is separately because its number and name can change depending on if were in it or not
    if (index_zero == 0) {
        mode_number = (uint8_t)Mode::Number::AUTO_RTL;
        name = "AUTO RTL";

    } else if (index_zero == 1) {
        mode_number = (uint8_t)Mode::Number::AUTO;
        name = "AUTO";

    }
#endif

    mavlink_msg_available_modes_send(
        chan,
        mode_count,
        index,
        MAV_STANDARD_MODE::MAV_STANDARD_MODE_NON_STANDARD,
        mode_number,
        0, // MAV_MODE_PROPERTY bitmask
        name
    );

    return mode_count;
}
