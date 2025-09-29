#include "GCS.h"
extern "C" {
#include <AP_KEM/vendor/pqclean/common/sha2.h>
}
#include <AP_KEM/ap_kem.h>
#include <AP_Param/AP_Param.h>
#include <AP_Math/AP_Math.h>
#include <AP_HAL/AP_HAL.h>
#include <AP_Math/crc.h>
#include <AP_Filesystem/AP_Filesystem.h>
#include <algorithm>
#include <cstring>

extern const AP_HAL::HAL& hal;

// send HQC_STATUS on a channel
static inline void send_hqc_status(mavlink_channel_t ch,
                                   uint64_t session_id,
                                   uint32_t value,
                                   uint8_t status,
                                   uint8_t detail)
{
    mavlink_msg_hqc_status_send(ch, session_id, value, status, detail);
}

static inline void send_hqc_abort(mavlink_channel_t ch,
                                  uint64_t session_id,
                                  uint8_t status,
                                  uint8_t detail,
                                  uint32_t value)
{
    mavlink_msg_hqc_abort_send(ch, session_id, status, detail, value);
}


static inline void le32(uint8_t out[4], uint32_t v){ out[0]=v&0xFF; out[1]=(v>>8)&0xFF; out[2]=(v>>16)&0xFF; out[3]=(v>>24)&0xFF; }
static inline void le64(uint8_t out[8], uint64_t v){ for (int i=0;i<8;i++) out[i]=(uint8_t)((v>>(8*i))&0xFF); }

static void th_update(uint8_t th[32], const uint8_t *msg, size_t len)
{
    // Simple: TH = SHA256( TH || msg )
    uint8_t buf[32 + (len>0?len:0)];
    memcpy(buf, th, 32);
    if (len) memcpy(buf+32, msg, len);
    sha256(th, buf, 32+len);
}

static void th_add_finish(uint8_t th[32], const mavlink_hqc_finish_t& in)
{
    uint8_t hdr[4 + 8 + 1 + 1];
    le32(&hdr[0], 61005u);                 
    le64(&hdr[4], in.session_id);         
    hdr[12] = in.role;
    hdr[13] = in.tag_len;

    th_update(th, hdr, sizeof(hdr));
    if (in.tag_len == 32) {
        th_update(th, in.tag, 32);
    } else if (in.tag_len > 0) {
        th_update(th, in.tag, in.tag_len);
    }
}

void GCS_MAVLINK::clamp_kex_params(HqcRxBuf& rx) {
    const uint16_t MTU_MAX = 220, MTU_MIN = 32;
    const uint8_t  WIN_MAX = 8,   WIN_MIN = 1;
    if (rx.mtu > MTU_MAX) rx.mtu = MTU_MAX;
    if (rx.mtu < MTU_MIN) rx.mtu = MTU_MIN;
    if (rx.window > WIN_MAX) rx.window = WIN_MAX;
    if (rx.window < WIN_MIN) rx.window = WIN_MIN;
}

// TH += canonical HELLO
static void th_add_hello(uint8_t th[32], const mavlink_hqc_hello_t& in)
{
    uint8_t h[4+8+4+1+1+1+1];
    le32(&h[0], 61000u);
    le64(&h[4], in.session_id);
    le32(&h[12], in.pk_len);
    h[16]=in.version; h[17]=in.suite_id; h[18]=in.flags; h[19]=in.aead_offer;
    th_update(th, h, sizeof(h));
    th_update(th, in.handshake_salt, 16);
    th_update(th, in.rc, 32);
}

static void th_add_abort(uint8_t th[32],
                         uint64_t session_id,
                         uint8_t status, uint8_t detail, uint32_t value)
{
    // Canonical ABORT record
    // fields: tag(61006) | session_id | status | detail | value(le32)
    uint8_t h[4 + 8 + 1 + 1 + 4];
    le32(&h[0], 61006u);
    le64(&h[4], session_id);
    h[12] = status;
    h[13] = detail;
    le32(&h[14], value);
    th_update(th, h, sizeof(h));
}


// TH += canonical HELLO_ACK
static void th_add_hello_ack(uint8_t th[32], const mavlink_hqc_hello_ack_t& ack)
{
    uint8_t h[4 + 8 + 2 + 1 + 1 + 1 + 1 + 4 + 4];

    le32(&h[0],  61001u);
    le64(&h[4],  ack.session_id);
    h[12] = (uint8_t)(ack.mtu & 0xFF);
    h[13] = (uint8_t)((ack.mtu >> 8) & 0xFF);
    h[14] = ack.window;
    h[15] = ack.required_alg;
    h[16] = ack.accept;
    h[17] = ack.status;
    le32(&h[18], ack.ct_e_len);
    le32(&h[22], ack.ct_s_len);

    th_update(th, h, sizeof(h));
    th_update(th, ack.rs, 32);
}

// Summarize the fully reassembled PK_E into TH (digest binds content without huge TH)
static void th_add_pk_summary(uint8_t th[32], uint64_t session_id, uint32_t pk_len, const uint8_t sha[32])
{
    uint8_t h[4+8+4];
    le32(&h[0],  61002u);       // HQC_PK_CHUNK message id tag (summary record)
    le64(&h[4],  session_id);
    le32(&h[12], pk_len);
    th_update(th, h, sizeof(h));
    th_update(th, sha, 32);
}

// Summarize a full CT (EPHEMERAL=0 / STATIC=1) into TH
static void th_add_ct_summary(uint8_t th[32], uint64_t session_id, uint8_t kind, uint32_t ct_len, const uint8_t sha[32])
{
    uint8_t h[4+8+1+4];
    le32(&h[0],  61003u);       // HQC_CT_CHUNK message id tag (summary record)
    le64(&h[4],  session_id);
    h[12] = kind;
    le32(&h[13], ct_len);
    th_update(th, h, sizeof(h));
    th_update(th, sha, 32);
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t out[32])
{
    uint8_t k0[64] = {0};
    if (klen > 64) { sha256(k0, key, klen); memset(k0+32, 0, 32); }
    else { memcpy(k0, key, klen); }

    uint8_t ipad[64], opad[64];
    for (size_t i=0;i<64;i++){ ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }

    uint8_t ihash[32];
    {   // inner = H(ipad || msg)
        uint8_t buf[64 + (mlen>0?mlen:0)];
        memcpy(buf, ipad, 64);
        if (mlen) memcpy(buf+64, msg, mlen);
        sha256(ihash, buf, 64+mlen);
    }
    {   // outer = H(opad || ihash)
        uint8_t buf[64+32];
        memcpy(buf, opad, 64);
        memcpy(buf+64, ihash, 32);
        sha256(out, buf, sizeof(buf));
    }
}

// HKDF-Extract(salt, IKM) -> PRK
static void hkdf_extract(const uint8_t salt[32], const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk_out[32])
{
    hmac_sha256(salt, 32, ikm, ikm_len, prk_out);
}

// HKDF-Expand(PRK, info, L) for L<=32
static void hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                        uint8_t out[32], size_t L)
{
    uint8_t T[32];
    uint8_t buf[32 + info_len + 1];
    // single block since L<=32
    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;
    hmac_sha256(prk, 32, buf, info_len+1, T);
    memcpy(out, T, L);
    volatile uint8_t z = 0; (void)z; // keep compiler from optimizing away
    memset(T, 0, sizeof(T));
}

// HKDF-Expand-Label style helper: out = HKDF-Expand(PRK, "ardupilot-hqc-v1:"||label||context, L)
static void hkdf_expand_label(const uint8_t prk[32],
                              const char *label, const uint8_t *context, size_t ctx_len,
                              uint8_t *out, size_t L)
{
    const char prefix[] = "ardupilot-hqc-v1:";
    uint8_t info[64];
    size_t lp = sizeof(prefix)-1, ll = strlen(label);
    size_t off=0;
    memcpy(info+off, prefix, lp); off+=lp;
    memcpy(info+off, label,  ll); off+=ll;
    if (ctx_len) { memcpy(info+off, context, ctx_len); off+=ctx_len; }
    hkdf_expand(prk, info, off, out, L);
}

static inline int ct_memcmp32(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t r = 0;
    for (size_t i=0;i<32;i++) r |= (uint8_t)(a[i]^b[i]);
    return r; // 0 if equal
}

bool GCS_MAVLINK::HqcSession::verify_finish_and_derive(const uint8_t peer_tag[32],
                                          const uint8_t th_in[32],
                                          const uint8_t ss_e[AP_KEM_BYTES],
                                          const uint8_t ss_s[AP_KEM_BYTES],
                                          const uint8_t salt[16],
                                          uint64_t session_id_le)
{
    uint8_t ikm[AP_KEM_BYTES*2];
    memcpy(ikm, ss_e, AP_KEM_BYTES);
    memcpy(ikm+AP_KEM_BYTES, ss_s, AP_KEM_BYTES);

    uint8_t saltbuf[16+8], salt32[32];
    memcpy(saltbuf,    salt, 16);
    memcpy(saltbuf+16, &session_id_le, 8);  // LE encoded
    sha256(salt32, saltbuf, sizeof(saltbuf));  // HKDF salt

    uint8_t prk[32];
    hkdf_extract(salt32, ikm, sizeof(ikm), prk); // RFC 5869 Extract

    uint8_t finished_key[32];
    hkdf_expand_label(prk, "finished", nullptr, 0, finished_key, 32); // Expand

    uint8_t exp_tag[32];
    hmac_sha256(finished_key, 32, th_in, 32, exp_tag); // HMAC over transcript hash

    uint8_t diff = 0;
    for (size_t i=0;i<32;i++) diff |= (uint8_t)(exp_tag[i]^peer_tag[i]);
    const bool ok = (diff == 0);
    if (!ok) {
        memset(exp_tag, 0, sizeof(exp_tag));
        memset(finished_key, 0, sizeof(finished_key));
        memset(prk, 0, sizeof(prk));
        memset(salt32, 0, sizeof(salt32));
        memset(ikm, 0, sizeof(ikm));
        return false;
    }

    // Session material (no activation here)
    hkdf_expand_label(prk, "ms",     nullptr, 0, ms,    32);
    hkdf_expand_label(prk, "key:tx", nullptr, 0, k_tx,  16);
    hkdf_expand_label(prk, "key:rx", nullptr, 0, k_rx,  16);
    hkdf_expand_label(prk, "iv:tx",  nullptr, 0, iv_tx, 12);
    hkdf_expand_label(prk, "iv:rx",  nullptr, 0, iv_rx, 12);

    memset(exp_tag, 0, sizeof(exp_tag));
    memset(finished_key, 0, sizeof(finished_key));
    memset(prk, 0, sizeof(prk));
    memset(salt32, 0, sizeof(salt32));
    memset(ikm, 0, sizeof(ikm));
    return true;
}

void GCS_MAVLINK::HqcSession::on_hello_start(GCS_MAVLINK* owner_, mavlink_channel_t ch, uint32_t now_ms)
{
    owner    = owner_;
    chan_hs  = ch;
    t_start  = now_ms;
    t_last_rx= now_ms;
    t_last_tx= now_ms;
}

void GCS_MAVLINK::HqcSession::note_rx(uint32_t now_ms)
{
    t_last_rx = now_ms;
}

void GCS_MAVLINK::HqcSession::tick(uint32_t now_ms)
{
    const uint32_t HS_TIMEOUT_MS = 20000;
    const uint32_t IDLE_NUDGE_MS = 1500;

    if (state == HqcState::IDLE || state == HqcState::FAIL || state == HqcState::ACTIVE) return;

    if (now_ms - t_start > HS_TIMEOUT_MS) {
        th_add_abort(th, rx.session_id, HQC_KEX_TIMEOUT, 2 /*GEN*/, 0);
        send_hqc_abort(chan_hs, rx.session_id, HQC_KEX_TIMEOUT, 2 /*GEN*/, 0);
        // hygiene
        this->reset();            // frees rx via rx.reset(), zeroes keys, etc.
        this->state = HqcState::FAIL;
        return;
    }

    pump_tx(now_ms);

    if (now_ms - t_last_rx > IDLE_NUDGE_MS) {
        kick_acks();
        t_last_rx = now_ms;
    }
}

void GCS_MAVLINK::HqcSession::pump_tx(uint32_t now_ms)
{
    const uint16_t mtu = rx.mtu;
    const uint32_t RTO_BASE_MS = 300;
    const uint32_t RTO_MAX_MS  = 4000;

    mavlink_message_t* const mbuf = owner ? owner->channel_buffer() : nullptr;
    if (!mbuf) return;

    auto all_acked = [](const std::vector<uint8_t>& v)->bool {
        if (v.empty()) return false;
        for (uint8_t b : v) if (!b) return false;
        return true;
    };

    auto rto_for = [&](uint8_t tries)->uint32_t {
        uint32_t r = RTO_BASE_MS;
        while (tries--) r = (r < RTO_MAX_MS) ? (r<<1) : RTO_MAX_MS;
        return r;
    };

    auto pump_stream = [&](uint8_t kind, uint8_t *ct, uint32_t len,
                           std::vector<uint8_t>& acked, uint32_t& sent_bytes)->bool
    {
        if (!ct || len == 0) return true;
        const uint32_t chunks = (len + mtu - 1U) / mtu;
        if (acked.size() != chunks) acked.assign(chunks, 0);

        uint32_t inflight = 0;
        for (uint32_t i = 0; i < chunks; i++) {
            const uint32_t off = i * mtu;
            if (!acked[i] && off < sent_bytes) inflight++;
        }

        for (uint32_t i = 0; i < chunks; i++) {
            const uint32_t off = i * mtu;
            if (off >= sent_bytes) break;
            if (acked[i]) continue;

            const uint8_t tries = rx.retries.count(off) ? rx.retries[off] : 0;
            const uint32_t rto  = rto_for(tries);
            if ((now_ms - t_last_tx) < rto) break;

            if (tries >= rx.max_retries) {
                // Canonical fail in TH, then abort + hygiene
                th_add_abort(th, rx.session_id, HQC_KEX_TIMEOUT, (kind==0)?0:1, off);
                send_hqc_abort(chan_hs, rx.session_id, HQC_KEX_TIMEOUT, (kind==0)?0:1, off);
                this->reset();
                this->state = HqcState::FAIL;
                return false;
            }

            const uint16_t n = (uint16_t)std::min<uint32_t>(mtu, len - off);
            uint8_t tmp[220] = {0};
            memcpy(tmp, ct + off, n);
            mavlink_msg_hqc_ct_chunk_send_buf(mbuf, chan_hs, rx.session_id, kind, off, n, tmp);
            rx.retries[off] = tries + 1;
            t_last_tx = now_ms;
            inflight++;
            break;
        }

        while (inflight < rx.window && sent_bytes < len) {
            const uint32_t off = sent_bytes;
            const uint16_t n   = (uint16_t)std::min<uint32_t>(mtu, len - off);
            uint8_t tmp[220] = {0};
            memcpy(tmp, ct + off, n);
            mavlink_msg_hqc_ct_chunk_send_buf(mbuf, chan_hs, rx.session_id, kind, off, n, tmp);
            sent_bytes += n;
            inflight++;
            t_last_tx = now_ms;
        }

        return true;
    };

    if (!pump_stream(/*EPH*/0, rx.cte, rx.cte_len, rx.cte_acked, rx.cte_sent)) return;
    if (!pump_stream(/*STA*/1, rx.cts, rx.cts_len, rx.cts_acked, rx.cts_sent)) return;

    const bool eph_done = all_acked(rx.cte_acked) && (rx.cte_len != 0);
    const bool sta_done = all_acked(rx.cts_acked) && (rx.cts_len != 0);
    if (eph_done && sta_done && state == HqcState::CT_TX) state = HqcState::WAIT_CF;
}

void GCS_MAVLINK::HqcSession::kick_acks()
{
    const uint16_t mtu = rx.mtu;
    mavlink_message_t* const mbuf = owner ? owner->channel_buffer() : nullptr;
    if (!mbuf) return;

    auto probe_stream = [&](uint8_t kind, uint8_t *ct, uint32_t len,
                            std::vector<uint8_t>& acked, uint32_t& sent_bytes)
    {
        if (!ct || len == 0) return;
        const uint32_t chunks = (len + mtu - 1U) / mtu;
        if (acked.size() != chunks) acked.assign(chunks, 0);

        uint32_t idx = 0;
        while (idx < chunks && acked[idx]) idx++;
        if (idx >= chunks) return;

        const uint32_t off = idx * mtu;
        const uint16_t n   = (uint16_t)std::min<uint32_t>(mtu, len - off);
        uint8_t tmp[220] = {0};
        memcpy(tmp, ct + off, n);
        mavlink_msg_hqc_ct_chunk_send_buf(mbuf, chan_hs, rx.session_id, kind, off, n, tmp);
        t_last_tx = AP_HAL::millis();
    };

    probe_stream(/*EPH*/0, rx.cte, rx.cte_len, rx.cte_acked, rx.cte_sent);
    probe_stream(/*STA*/1, rx.cts, rx.cts_len, rx.cts_acked, rx.cts_sent);
}

void GCS_MAVLINK::HqcSession::reset()
{
    memset(th,    0, sizeof(th));
    memset(ms,    0, sizeof(ms));
    memset(k_tx,  0, sizeof(k_tx));
    memset(k_rx,  0, sizeof(k_rx));
    memset(iv_tx, 0, sizeof(iv_tx));
    memset(iv_rx, 0, sizeof(iv_rx));

    rx.reset();

    state             = HqcState::IDLE;
    suite_kem         = 1;
    aead_alg          = 1;
    negotiated_mtu    = 220;
    negotiated_window = 8;

    t_last_rx     = 0;
    t_last_tx     = 0;
    retries_total = 0;
}

void GCS_MAVLINK::HqcSession::start_encap()
{
    if (!rx.pke) { state = HqcState::FAIL; return; }
    if (!rx.cte) { rx.cte = (uint8_t*)malloc(AP_KEM_CIPHERTEXTBYTES); }
    if (!rx.cte) { state = HqcState::FAIL; return; }

    // ss length is AP_KEM_BYTES; ct length is AP_KEM_CIPHERTEXTBYTES
    uint8_t ss_tmp[AP_KEM_BYTES] = {0};
    if (!ap_kem_enc(rx.cte, ss_tmp, rx.pke)) { state = HqcState::FAIL; return; }

    memset(rx.ss_e, 0, sizeof(rx.ss_e));
    memcpy(rx.ss_e, ss_tmp, std::min(sizeof(rx.ss_e), sizeof(ss_tmp)));

    rx.cte_len = AP_KEM_CIPHERTEXTBYTES;
    rx.cte_acked.assign((rx.cte_len + rx.mtu - 1U) / rx.mtu, 0);
    state = HqcState::ENCAP_DONE;
}

void GCS_MAVLINK::handle_hqc_hello(const mavlink_message_t& msg)
{
    hqc_.reset();

    mavlink_hqc_hello_t in{};
    mavlink_msg_hqc_hello_decode(&msg, &in);

    HqcRxBuf& rx = hqc_.rx;
    rx.session_id = in.session_id;
    rx.pk_len     = in.pk_len;
    rx.version    = in.version;
    rx.suite_id   = in.suite_id;
    rx.flags      = in.flags;
    rx.aead_offer = in.aead_offer;
    memcpy(rx.salt, in.handshake_salt, 16);
    memcpy(rx.rc,   in.rc,             32);

    clamp_kex_params(rx);
    hqc_.negotiated_mtu    = rx.mtu;
    hqc_.negotiated_window = rx.window;

    const mavlink_channel_t ch    = this->get_chan();
    mavlink_message_t* const mbuf = this->channel_buffer();

    hqc_.on_hello_start(this, ch, AP_HAL::millis());

    // TH += canonical HELLO
    th_add_hello(hqc_.th, in);

    // Rejects and errors produce a canonical HELLO_ACK (nack) into TH, then send.
    auto send_nack = [&](uint8_t status, uint8_t detail_log, const char* fmt, unsigned v){
        mavlink_hqc_hello_ack_t nack{};
        nack.session_id = rx.session_id;
        nack.mtu = rx.mtu; nack.window = rx.window;
        nack.required_alg = 1; nack.accept = 0; nack.status = status;
        nack.ct_e_len = 0; nack.ct_s_len = 0; memset(nack.rs, 0, 32);
        th_add_hello_ack(hqc_.th, nack);
        mavlink_msg_hqc_hello_ack_send_buf(mbuf, ch, nack.session_id, nack.mtu, nack.window,
                                           nack.required_alg, nack.accept, nack.status,
                                           nack.ct_e_len, nack.ct_s_len, nack.rs);
        send_text(MAV_SEVERITY_ERROR, fmt, v);
    };

    if (rx.version != 1) { send_nack(HQC_KEX_REJECTED, 0, "HQC: unsupported version %u", (unsigned)rx.version); return; }
    if (rx.suite_id != 1){ send_nack(HQC_KEX_REJECTED, 0, "HQC: suite not supported (%u)", (unsigned)rx.suite_id); return; }
    if (rx.pk_len == 0 || rx.pk_len > 65536U) {send_nack(HQC_KEX_BAD_LEN, 0, "HQC: bad pk_len=%u", (unsigned)rx.pk_len); return;}
    if (rx.aead_offer != 1){ send_nack(HQC_KEX_REJECTED, 0, "HQC: unsupported AEAD offer (%u)", (unsigned)rx.aead_offer); return;}

    rx.pke = (uint8_t*)malloc(rx.pk_len);
    if (!rx.pke) { send_nack(HQC_KEX_INTERNAL, 1, "HQC: malloc pke failed", 0); return; }

    // --- PDK load/parse (unchanged except cleanup paths) ---
    AP_Filesystem::stat_t stfile{};
    if (!AP::FS().stat("APM/CFG/kemtls_pk.bin", stfile) || stfile.size < 56) {
        send_nack(HQC_KEX_ENC_UNAV, 0, "HQC: PDK not found or too small", 0);
        free(rx.pke); rx.pke=nullptr; return;
    }
    int fd = AP::FS().open("APM/CFG/kemtls_pk.bin", O_RDONLY);
    if (fd < 0) { send_nack(HQC_KEX_INTERNAL, 0, "HQC: open PDK failed", 0); free(rx.pke); rx.pke=nullptr; return; }

    uint8_t hdr[56];
    if (AP::FS().read(fd, hdr, sizeof(hdr)) != (int32_t)sizeof(hdr)) {
        AP::FS().close(fd); send_nack(HQC_KEX_INTERNAL, 0, "HQC: PDK header read failed", 0); free(rx.pke); rx.pke=nullptr; return;
    }
    auto rd16 = [](const uint8_t* p)->uint16_t { return (uint16_t)p[0] | ((uint16_t)p[1]<<8); };
    auto rd32 = [](const uint8_t* p)->uint32_t { return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); };
    auto rd64 = [&](const uint8_t* p)->uint64_t { uint64_t v=0; for (int i=7;i>=0;i--) v=(v<<8)|p[i]; return v; };

    const uint32_t magic   = rd32(&hdr[0]);
    const uint16_t ver     = rd16(&hdr[4]);
    const uint8_t  suite   = hdr[6];
    const uint8_t  alg     = hdr[7];
    (void)rd64(&hdr[8]);
    const uint32_t pksz    = rd32(&hdr[16]);
    const uint8_t* fp_hdr  = &hdr[20];


    AP_Filesystem::stat_t stfile2{};
    if (magic != 0x544D454B || ver != 1 || suite != 1 ||
        !AP::FS().stat("APM/CFG/kemtls_pk.bin", stfile2) ||
        stfile2.size < 56U + pksz || pksz == 0 || pksz > 65536U) {
        AP::FS().close(fd); send_nack(HQC_KEX_INTERNAL, 0, "HQC: bad PDK header/suite/size (pksz=%u)", (unsigned)pksz);
        free(rx.pke); rx.pke=nullptr; return;
    }

    const uint32_t PK_BYTES = (uint32_t)AP_KEM_PUBLICKEYBYTES;
    rx.pks = (uint8_t*)calloc(PK_BYTES, 1);
    if (!rx.pks) { AP::FS().close(fd); send_hqc_status(ch, rx.session_id, 0, HQC_KEX_INTERNAL, 2); send_text(MAV_SEVERITY_ERROR, "HQC: malloc pks(%u) failed", (unsigned)PK_BYTES); free(rx.pke); rx.pke=nullptr; return; }

    { uint32_t got = 0; while (got < pksz) { const int32_t r = AP::FS().read(fd, rx.pks + got, pksz - got);
        if (r <= 0) { AP::FS().close(fd); send_hqc_status(ch, rx.session_id, 0, HQC_KEX_INTERNAL, 3); send_text(MAV_SEVERITY_ERROR, "HQC: read pks short (%u/%u)", (unsigned)got, (unsigned)pksz);
            free(rx.pks); rx.pks=nullptr; free(rx.pke); rx.pke=nullptr; return; } got += (uint32_t)r; } }
    AP::FS().close(fd);

    if (pksz != PK_BYTES) send_text(MAV_SEVERITY_WARNING, "HQC: pksz(%u) != AP_KEM_PUBLICKEYBYTES(%u) — possible mismatch", (unsigned)pksz, (unsigned)PK_BYTES);

    uint8_t fp_calc[32]; sha256(fp_calc, rx.pks, pksz);
    if (memcmp(fp_calc, fp_hdr, 32) != 0) {
        char hdrhex[65], calchex[65]; for (int i=0;i<32;i++) { snprintf(hdrhex+2*i,3,"%02X",fp_hdr[i]); snprintf(calchex+2*i,3,"%02X",fp_calc[i]); } hdrhex[64]=0; calchex[64]=0;
        send_text(MAV_SEVERITY_ERROR, "HQC: PDK fp mismatch hdr=%s calc=%s", hdrhex, calchex);
        mavlink_hqc_hello_ack_t nack{}; nack.session_id = rx.session_id; nack.mtu = rx.mtu; nack.window = rx.window;
        nack.required_alg = 1; nack.accept = 0; nack.status = HQC_KEX_INTERNAL; nack.ct_e_len = 0; nack.ct_s_len = 0; memset(nack.rs, 0, 32);
        th_add_hello_ack(hqc_.th, nack);
        mavlink_msg_hqc_hello_ack_send_buf(mbuf, ch, nack.session_id, nack.mtu, nack.window, nack.required_alg, nack.accept, nack.status, nack.ct_e_len, nack.ct_s_len, nack.rs);
        free(rx.pks); rx.pks=nullptr; free(rx.pke); rx.pke=nullptr; return;
    }

    send_text(MAV_SEVERITY_INFO, "HQC: suite=%u alg=%u pksz=%u pkbytes=%u ctbytes=%u",
              (unsigned)suite, (unsigned)alg, (unsigned)pksz, (unsigned)PK_BYTES, (unsigned)AP_KEM_CIPHERTEXTBYTES);

    rx.cts = (uint8_t*)malloc(AP_KEM_CIPHERTEXTBYTES);
    if (!rx.cts) { send_nack(HQC_KEX_INTERNAL, 4, "HQC: malloc cts failed", 0); free(rx.pks); rx.pks=nullptr; free(rx.pke); rx.pke=nullptr; return; }

    {
        uint8_t ss_tmp[AP_KEM_BYTES] = {0};
        const int rc = ap_kem_enc(rx.cts, ss_tmp, rx.pks);
        if (!rc) {
            char fphex[65]; for (int i=0;i<32;i++) snprintf(fphex + 2*i, 3, "%02X", fp_calc[i]); fphex[64] = '\0';
            send_text(MAV_SEVERITY_ERROR, "HQC: kem_enc rc=%d pksz=%u pkbytes=%u ctbytes=%u",
                    rc, (unsigned)pksz, (unsigned)PK_BYTES, (unsigned)AP_KEM_CIPHERTEXTBYTES);
            send_text(MAV_SEVERITY_INFO,  "HQC: pk_sha256=%s", fphex);
            send_nack(HQC_KEX_ENC_UNAV, 0, "HQC: kem enc unavailable (%u)", (unsigned)rc);
            free(rx.cts); rx.cts=nullptr; free(rx.pks); rx.pks=nullptr; free(rx.pke); rx.pke=nullptr;
            return;
        }
        rx.cts_len = AP_KEM_CIPHERTEXTBYTES;
        rx.cts_acked.assign((rx.cts_len + rx.mtu - 1U) / rx.mtu, 0);
        memset(rx.ss_s, 0, sizeof(rx.ss_s));
        memcpy(rx.ss_s, ss_tmp, std::min<size_t>(sizeof(rx.ss_s), sizeof(ss_tmp)));
    }

    // rs = SHA256(session_id || salt || fp_hdr)
    { uint8_t buf[8 + 16 + 32]; memcpy(buf, &rx.session_id, 8); memcpy(buf + 8, rx.salt, 16); memcpy(buf + 24, fp_hdr, 32); sha256(rx.rs, buf, sizeof(buf)); }

    const uint32_t ct_len_ephem  = AP_KEM_CIPHERTEXTBYTES;
    const uint32_t ct_len_static = AP_KEM_CIPHERTEXTBYTES;

    // TH += summary of CT_STATIC we just produced
    { uint8_t cts_sha[32]; sha256(cts_sha, rx.cts, rx.cts_len);
      th_add_ct_summary(hqc_.th, rx.session_id, /*STATIC*/1, rx.cts_len, cts_sha); }

    hqc_.state = HqcState::HELLO_RCVD;

    // Build/send ACK (and feed TH with its canonical bytes)
    mavlink_hqc_hello_ack_t ack{};
    ack.session_id   = rx.session_id;
    ack.mtu          = rx.mtu;
    ack.window       = rx.window;
    ack.required_alg = 1;
    ack.accept       = 1;
    ack.status       = HQC_KEX_IN_PROGRESS;
    ack.ct_e_len     = ct_len_ephem;
    ack.ct_s_len     = ct_len_static;
    memcpy(ack.rs, rx.rs, 32);

    th_add_hello_ack(hqc_.th, ack);

    mavlink_msg_hqc_hello_ack_send_buf(mbuf, ch, ack.session_id, ack.mtu, ack.window,
                                       ack.required_alg, ack.accept, ack.status,
                                       ack.ct_e_len, ack.ct_s_len, ack.rs);

    // First window of CT_STATIC
    {
        uint32_t off = 0; uint8_t sent = 0;
        while (off < ct_len_static && sent < rx.window) {
            const uint16_t n = (uint16_t)std::min<uint32_t>(rx.mtu, ct_len_static - off);
            uint8_t tmp[220] = {0};
            memcpy(tmp, rx.cts + off, n);
            mavlink_msg_hqc_ct_chunk_send_buf(mbuf, ch, rx.session_id, 1 /* STATIC */, off, n, tmp);
            off += n; sent++;
        }
        rx.cts_sent = off;
    }

    hqc_.state = HqcState::CT_TX;
}


void GCS_MAVLINK::handle_hqc_pk_chunk(const mavlink_message_t& msg)
{
    hqc_.note_rx(AP_HAL::millis());
    mavlink_hqc_pk_chunk_t m{};
    mavlink_msg_hqc_pk_chunk_decode(&msg, &m);
    

    HqcRxBuf& rx = hqc_.rx;
    const mavlink_channel_t ch = this->get_chan();
    mavlink_message_t* const mbuf = this->channel_buffer();

    if (m.session_id != rx.session_id) { send_hqc_status(ch, rx.session_id, 0, HQC_KEX_BAD_SEQ, 1); return; }
    if (rx.pk_len == 0 || rx.pke == nullptr) { send_hqc_status(ch, rx.session_id, 0, HQC_KEX_INTERNAL, 10); return; }
    if (m.count == 0 || m.count > rx.mtu) { send_hqc_status(ch, rx.session_id, m.count, HQC_KEX_BAD_LEN, 2); return; }
    if (m.offset > rx.pk_len || (uint64_t)m.offset + (uint64_t)m.count > (uint64_t)rx.pk_len) { send_hqc_status(ch, rx.session_id, m.offset, HQC_KEX_BAD_LEN, 3); return; }

    const bool is_last = ((uint32_t)m.offset + (uint32_t)m.count) == rx.pk_len;
    if ((m.offset % rx.mtu) != 0 && !is_last) { send_hqc_status(ch, rx.session_id, m.offset, HQC_KEX_BAD_SEQ, 4); return; }

    const uint32_t frag_idx = (uint32_t)m.offset / (uint32_t)rx.mtu;
    const uint32_t total_frags = rx.pk_chunks();
    if (frag_idx >= total_frags) { send_hqc_status(ch, rx.session_id, frag_idx, HQC_KEX_BAD_SEQ, 5); return; }

    if (rx.pke_acked.empty()) { rx.pke_acked.assign(total_frags, 0); }

    if (!rx.pke_acked[frag_idx]) {
        memcpy(rx.pke + m.offset, m.data, m.count);
        rx.pke_acked[frag_idx] = 1;
    }

    // advance base and SACK
    uint32_t base_frag = rx.pke_rcvd / rx.mtu;
    while (base_frag < total_frags && rx.pke_acked[base_frag]) base_frag++;
    uint32_t new_base_bytes = base_frag * (uint32_t)rx.mtu;
    if (new_base_bytes > rx.pk_len) new_base_bytes = rx.pk_len;
    rx.pke_rcvd = new_base_bytes;

    uint32_t mask = 0;
    for (uint32_t i = 0; i < 32; i++) {
        const uint32_t idx = base_frag + i;
        if (idx < total_frags && rx.pke_acked[idx]) mask |= (1u << i);
    }

    mavlink_msg_hqc_pk_ack_send_buf(mbuf, ch, rx.session_id, rx.pke_rcvd, mask);

    if (rx.pke_rcvd >= rx.pk_len) {
        // TH += PK_E digest (bind the exact public key content)
        { uint8_t pk_sha[32]; sha256(pk_sha, rx.pke, rx.pk_len);
          th_add_pk_summary(hqc_.th, rx.session_id, rx.pk_len, pk_sha); }

        hqc_.state = HqcState::ENCAP_READY;
        hqc_.start_encap();
        if (hqc_.state != HqcState::ENCAP_DONE) { send_text(MAV_SEVERITY_ERROR, "HQC: encap(ephemeral) failed"); return; }

        // TH += CT_EPHEMERAL digest (bind the ciphertext we just created)
        if (rx.cte && rx.cte_len) { uint8_t cte_sha[32]; sha256(cte_sha, rx.cte, rx.cte_len);
            th_add_ct_summary(hqc_.th, rx.session_id, /*EPHEMERAL*/0, rx.cte_len, cte_sha); }

        // send first window of CT_EPHEMERAL
        uint32_t off = 0; uint8_t sent = 0;
        while (off < rx.cte_len && sent < rx.window) {
            const uint16_t n = (uint16_t)std::min<uint32_t>(rx.mtu, rx.cte_len - off);
            uint8_t tmp[220] = {0};
            memcpy(tmp, rx.cte + off, n);
            mavlink_msg_hqc_ct_chunk_send_buf(mbuf, ch, rx.session_id, /*ct_kind*/0, off, n, tmp);
            off += n; sent++;
        }
        rx.cte_sent = off;
        hqc_.state = HqcState::CT_TX;
    }
}

void GCS_MAVLINK::handle_hqc_ct_ack(const mavlink_message_t& msg)
{
    hqc_.note_rx(AP_HAL::millis());
    mavlink_hqc_ct_ack_t in{};
    mavlink_msg_hqc_ct_ack_decode(&msg, &in);

    HqcRxBuf &rx = hqc_.rx;
    if (in.session_id != rx.session_id) { return; }
    const uint16_t mtu = rx.mtu;
    const mavlink_channel_t ch = this->get_chan();
    mavlink_message_t* const mbuf = this->channel_buffer();

    const uint8_t kind = in.ct_kind;          // 0=ephemeral, 1=static
    uint8_t *ct = (kind==0) ? rx.cte : rx.cts;
    uint32_t len = (kind==0) ? rx.cte_len : rx.cts_len;
    auto &acked = (kind==0) ? rx.cte_acked : rx.cts_acked;
    uint32_t &sent_bytes = (kind==0) ? rx.cte_sent : rx.cts_sent;

    if (!ct || len == 0) { return; }
    const uint32_t chunks = (len + mtu - 1U) / mtu;
    if (acked.size() != chunks) { acked.assign(chunks, 0); }

    const uint32_t base = in.base;
    const uint32_t base_idx = base / mtu;
    for (uint32_t i = 0; i < std::min(base_idx, (uint32_t)acked.size()); i++) acked[i] = 1;

    uint32_t mask = in.mask;
    for (uint32_t i = 0; i < 32; i++) {
        const uint32_t idx = base_idx + i;
        if (idx >= chunks) break;
        if (mask & 1U) acked[idx] = 1;
        mask >>= 1U;
    }

    // NEW: drop retry counters for acked offsets
    for (uint32_t i = 0; i < chunks; i++) {
        if (acked[i]) {
            const uint32_t off = i * mtu;
            auto it = rx.retries.find(off);
            if (it != rx.retries.end()) rx.retries.erase(it);
        }
    }

    uint32_t inflight = 0;
    for (uint32_t i = 0; i < chunks; i++) {
        if (!acked[i] && (i*mtu) < sent_bytes) inflight++;
    }

    uint32_t sent_now = 0;
    for (uint32_t i = 0; i < chunks && (sent_now + inflight) < rx.window; i++) {
        if (acked[i]) continue;
        const uint32_t off = i * mtu;
        if (off < sent_bytes && rx.retries[off] >= rx.max_retries) continue;

        const uint16_t n = (uint16_t)std::min<uint32_t>(mtu, len - off);
        uint8_t tmp[220] = {0};
        memcpy(tmp, ct + off, n);
        mavlink_msg_hqc_ct_chunk_send_buf(mbuf, ch, rx.session_id, kind, off, n, tmp);

        sent_bytes = std::max<uint32_t>(sent_bytes, off + n);
        if (off < sent_bytes) rx.retries[off]++;
        sent_now++;
    }

    auto all_acked = [](const std::vector<uint8_t>& v)->bool {
        if (v.empty()) return false;
        for (uint8_t b : v) { if (!b) return false; }
        return true;
    };

    const bool eph_done = all_acked(rx.cte_acked) && (rx.cte_len != 0);
    const bool sta_done = all_acked(rx.cts_acked) && (rx.cts_len != 0);

    if (eph_done && sta_done) {
        hqc_.state = HqcState::WAIT_CF;
        // optional: shrink retry map once both streams done
        rx.retries.clear();
    }
}

void GCS_MAVLINK::handle_hqc_finish(const mavlink_message_t& msg)
{
    hqc_.note_rx(AP_HAL::millis());
    mavlink_hqc_finish_t in{};
    mavlink_msg_hqc_finish_decode(&msg, &in);

    HqcRxBuf &rx = hqc_.rx;
    const mavlink_channel_t ch = this->get_chan();

    // Basic session/state checks
    if (in.session_id != rx.session_id) {
        send_hqc_status(ch, rx.session_id, 0, HQC_KEX_BAD_SEQ, 20);
        return;
    }
    if (hqc_.state != HqcState::WAIT_CF) {
        send_hqc_status(ch, rx.session_id, 0, HQC_KEX_IN_PROGRESS, 22);
        return;
    }
    if (in.role != 1 /* GCS client */) {
        send_hqc_status(ch, rx.session_id, in.role, HQC_KEX_BAD_SEQ, 23);
        return;
    }
    if (in.tag_len != 32) {
        send_hqc_status(ch, rx.session_id, in.tag_len, HQC_KEX_BAD_LEN, 24);
        return;
    }

    // Both CTs must be fully ACKed
    auto all_acked = [](const std::vector<uint8_t>& v)->bool {
        if (v.empty()) return false;
        for (uint8_t b : v) { if (!b) return false; }
        return true;
    };
    const bool eph_done = all_acked(rx.cte_acked) && (rx.cte_len != 0);
    const bool sta_done = all_acked(rx.cts_acked) && (rx.cts_len != 0);
    if (!(eph_done && sta_done)) {
        send_hqc_status(ch, rx.session_id, 0, HQC_KEX_IN_PROGRESS, 21);
        return;
    }

    // LE session_id for salt binding
    uint64_t sid_le = 0; {
        uint8_t *p=(uint8_t*)&sid_le;
        for (int i=0;i<8;i++) p[i]=(uint8_t)((rx.session_id>>(8*i))&0xFF);
    }

    // Verify FINISH and derive session material (no activation yet)
    const bool ok = hqc_.verify_finish_and_derive(in.tag, hqc_.th, rx.ss_e, rx.ss_s, rx.salt, sid_le);
    if (!ok) {
        // Canonical failure path: bind ABORT into TH, notify, and clean up
        th_add_abort(hqc_.th, rx.session_id, HQC_KEX_REJECTED, 31, 0);
        send_hqc_status(ch, rx.session_id, 0, HQC_KEX_REJECTED, 31);
        hqc_.reset();
        hqc_.state = HqcState::FAIL;
        return;
    }

    // Success path: bind FINISH canonically
    th_add_finish(hqc_.th, in);

    // --- Derive MAVLink signing key and enable signing on this link ---
    // PRK = HKDF-Extract( SHA256( salt || LE(session_id) ), ss_e || ss_s )
    // k_sign = HKDF-Expand-Label(PRK, "sign", 32)
    uint8_t k_sign[32] = {0};
    {
        uint8_t ikm[AP_KEM_BYTES*2];
        memcpy(ikm, rx.ss_e, AP_KEM_BYTES);
        memcpy(ikm+AP_KEM_BYTES, rx.ss_s, AP_KEM_BYTES);

        uint8_t saltbuf[16+8], salt32[32], prk[32];
        memcpy(saltbuf, rx.salt, 16);
        memcpy(saltbuf+16, &sid_le, 8);
        sha256(salt32, saltbuf, sizeof(saltbuf));

        hkdf_extract(salt32, ikm, sizeof(ikm), prk);
        hkdf_expand_label(prk, "sign", nullptr, 0, k_sign, sizeof(k_sign));

        // wipe temps
        memset(prk, 0, sizeof(prk));
        memset(salt32, 0, sizeof(salt32));
        memset(ikm, 0, sizeof(ikm));
        memset(saltbuf, 0, sizeof(saltbuf));
    }

#if AP_MAVLINK_SIGNING_ENABLED
    // Enable MAVLink2 signing on this channel immediately.
    // initial_timestamp_10us = 0 (library runs in 10µs ticks from 2015-01-01 epoch, and will
    // bump/learn; GPS later calls update_signing_timestamp()).
    // persist=false keeps this session-ephemeral unless you decide to store it.
    enable_signing_with_key(k_sign, /*initial_timestamp_10us=*/0ULL, /*persist=*/false);
#endif

    // Free big buffers
    if (rx.pke) { free(rx.pke); rx.pke = nullptr; }
    if (rx.cte) { free(rx.cte); rx.cte = nullptr; }
    if (rx.cts) { free(rx.cts); rx.cts = nullptr; }

    // Done
    hqc_.state = HqcState::ACTIVE;
    send_hqc_status(ch, rx.session_id, 0, HQC_KEX_OK, 0);
}
