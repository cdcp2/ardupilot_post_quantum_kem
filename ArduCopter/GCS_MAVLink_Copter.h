#pragma once

#ifndef AC_MAVLINK_SOLO_BUTTON_COMMAND_HANDLING_ENABLED
#define AC_MAVLINK_SOLO_BUTTON_COMMAND_HANDLING_ENABLED 1
#endif


#include <GCS_MAVLink/GCS.h>
#include <AP_Winch/AP_Winch_config.h>
#include "defines.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <unordered_map>


// ---------- Sesión de cifrado (tras HQC) ----------
struct CryptoSession {
    bool     active = false;
    uint8_t  session_id = 0;
    uint16_t rx_last_seq = 0;
    uint16_t tx_next_seq = 1;
    uint64_t start_ms = 0;

    // DEPRECATED (mantener mientras migras a claves direccionales)
    uint8_t  key[16] = {0};
    uint8_t  nonce_base[16] = {0};

    //claves y nonces direccionales para AEAD
    uint8_t  key_tx[16] = {0};        // FC -> GCS
    uint8_t  key_rx[16] = {0};        // GCS -> FC
    uint8_t  nonce_base_tx[16] = {0}; // FC -> GCS
    uint8_t  nonce_base_rx[16] = {0}; // GCS -> FC

    //clave de firmado MAVLink v2 (32B)
    uint8_t  k_sig[32] = {0};

    //anti-replay para CRYPTO_PKT (ventana deslizante de 64)
    uint64_t replay_window = 0;  // bitmap de vistos
    uint16_t replay_base   = 0;  // secuencia base de la ventana

    void set_keys(const uint8_t ktx[16], const uint8_t krx[16],
                    const uint8_t ntx[16], const uint8_t nrx[16])
    {
        memcpy(key_tx, ktx, 16);
        memcpy(key_rx, krx, 16);
        memcpy(nonce_base_tx, ntx, 16);
        memcpy(nonce_base_rx, nrx, 16);
        // reset de estado de sesión/anti-replay
        replay_window = 0;
        replay_base   = 0;
        rx_last_seq   = 0;
        tx_next_seq   = 1;
    }

    void set_signing_key(const uint8_t ksig[32])
    {
        memcpy(k_sig, ksig, 32);
    }
};

// Forward decls
struct AP_AEAD_Sizes;
class  AP_CryptoAEAD;
AP_CryptoAEAD* AP_Crypto_GetAEAD_Ascon();

class GCS_MAVLINK_Copter : public GCS_MAVLINK
{
public:
    using GCS_MAVLINK::GCS_MAVLINK;

    // Handlers HQC y CRYPTO
    void handle_crypto_pkt(const mavlink_message_t& msg);
    void handle_hqc_hello(const mavlink_message_t& msg);
    void handle_hqc_pk_chunk(const mavlink_message_t& msg);
    void handle_hqc_ct_ack(const mavlink_message_t& msg);
    void handle_hqc_finish(const mavlink_message_t& msg);

    // Envoltura para enviar un inner MAVLink cifrado
    bool send_crypto_pkt_wrapped(const mavlink_message_t& inner);

    // Tabla de parámetros de ESTA clase:
    static const AP_Param::GroupInfo var_info_crypto[];

    bool crypto_params_registered_ = false;

protected:

    MAV_RESULT handle_flight_termination(const mavlink_command_int_t &packet) override;

    bool params_ready() const override;
    void send_banner() override;

    MAV_RESULT _handle_command_preflight_calibration(const mavlink_command_int_t &packet, const mavlink_message_t &msg) override;

    void send_attitude_target() override;
    void send_position_target_global_int() override;
    void send_position_target_local_ned() override;

    MAV_RESULT handle_command_do_set_roi(const Location &roi_loc) override;
    MAV_RESULT handle_preflight_reboot(const mavlink_command_int_t &packet, const mavlink_message_t &msg) override;
#if HAL_MOUNT_ENABLED
    MAV_RESULT handle_command_mount(const mavlink_command_int_t &packet, const mavlink_message_t &msg) override;
#endif
    MAV_RESULT handle_command_int_packet(const mavlink_command_int_t &packet, const mavlink_message_t &msg) override;
    MAV_RESULT handle_command_int_do_reposition(const mavlink_command_int_t &packet);
    MAV_RESULT handle_command_pause_continue(const mavlink_command_int_t &packet);

#if HAL_MOUNT_ENABLED
    void handle_mount_message(const mavlink_message_t &msg) override;
#endif

    void handle_message_set_attitude_target(const mavlink_message_t &msg);
    void handle_message_set_position_target_global_int(const mavlink_message_t &msg);
    void handle_message_set_position_target_local_ned(const mavlink_message_t &msg);

    void handle_landing_target(const mavlink_landing_target_t &packet, uint32_t timestamp_ms) override;

    void send_nav_controller_output() const override;
    uint64_t capabilities() const override;

    virtual MAV_VTOL_STATE vtol_state() const override { return MAV_VTOL_STATE_MC; };
    virtual MAV_LANDED_STATE landed_state() const override;

    void handle_manual_control_axes(const mavlink_manual_control_t &packet, const uint32_t tnow) override;

#if HAL_LOGGING_ENABLED
    uint32_t log_radio_bit() const override { return MASK_LOG_PM; }
#endif

    // Send the mode with the given index (not mode number!) return the total number of modes
    // Index starts at 1
    uint8_t send_available_mode(uint8_t index) const override;

private:

    // sanity check velocity or acceleration vector components are numbers
    // (e.g. not NaN) and below 1000. vec argument units are in meters/second or
    // metres/second/second
    bool sane_vel_or_acc_vector(const Vector3f &vec) const;

    MISSION_STATE mission_state(const class AP_Mission &mission) const override;

    void handle_message(const mavlink_message_t &msg) override;
    void handle_command_ack(const mavlink_message_t &msg) override;
    bool handle_guided_request(AP_Mission::Mission_Command &cmd) override;
    bool try_send_message(enum ap_message id) override;

    void packetReceived(const mavlink_status_t &status,
                        const mavlink_message_t &msg) override;

    uint8_t base_mode() const override;
    MAV_STATE vehicle_system_status() const override;

    float vfr_hud_airspeed() const override;
    int16_t vfr_hud_throttle() const override;
    float vfr_hud_alt() const override;

    void send_pid_tuning() override;

#if AP_WINCH_ENABLED
    void send_winch_status() const override;
#endif

    void send_wind() const;

#if HAL_HIGH_LATENCY2_ENABLED
    int16_t high_latency_target_altitude() const override;
    uint8_t high_latency_tgt_heading() const override;
    uint16_t high_latency_tgt_dist() const override;
    uint8_t high_latency_tgt_airspeed() const override;
    uint8_t high_latency_wind_speed() const override;
    uint8_t high_latency_wind_direction() const override;
#endif // HAL_HIGH_LATENCY2_ENABLED


    MAV_RESULT handle_MAV_CMD_CONDITION_YAW(const mavlink_command_int_t &packet);
    MAV_RESULT handle_MAV_CMD_DO_CHANGE_SPEED(const mavlink_command_int_t &packet);
    MAV_RESULT handle_MAV_CMD_DO_MOTOR_TEST(const mavlink_command_int_t &packet);
    MAV_RESULT handle_MAV_CMD_DO_PARACHUTE(const mavlink_command_int_t &packet);

#if AC_MAVLINK_SOLO_BUTTON_COMMAND_HANDLING_ENABLED
    MAV_RESULT handle_MAV_CMD_SOLO_BTN_FLY_CLICK(const mavlink_command_int_t &packet);
    MAV_RESULT handle_MAV_CMD_SOLO_BTN_FLY_HOLD(const mavlink_command_int_t &packet);
    MAV_RESULT handle_MAV_CMD_SOLO_BTN_PAUSE_CLICK(const mavlink_command_int_t &packet);
#endif

#if AP_MAVLINK_COMMAND_LONG_ENABLED
    bool mav_frame_for_command_long(MAV_FRAME &frame, MAV_CMD packet_command) const override;
#endif

    MAV_RESULT handle_MAV_CMD_MISSION_START(const mavlink_command_int_t &packet);
    MAV_RESULT handle_MAV_CMD_NAV_TAKEOFF(const mavlink_command_int_t &packet);

#if AP_WINCH_ENABLED
    MAV_RESULT handle_MAV_CMD_DO_WINCH(const mavlink_command_int_t &packet);
#endif

    // -------- Utilidades ----------
    bool  crypto_gate_open() const;
    bool  crypto_rate_allow();

    // CHANGED: nonces direccionales (antes: nonce_from_seq())
    void  nonce_from_seq_tx(uint16_t seq, uint8_t out16[16]) const; // NEW
    void  nonce_from_seq_rx(uint16_t seq, uint8_t out16[16]) const; // NEW

    // NEW: AD para AEAD (igual que antes, pero mantenla pública si la usas fuera)
    void  build_ad(uint8_t session, uint16_t seq, uint8_t out8[8]) const;

    // NEW: verificación/actualización de anti-replay para CRYPTO_PKT
    bool  window_accept_and_update(uint16_t seq);

    // NEW: callback MAVLink para permitir ciertos mensajes sin firma
    // (firma requerida en MAVLink v2; prototipo coincide con mavlink_accept_unsigned_t)
    static bool accept_unsigned_cb(const mavlink_status_t* status, uint32_t msgid);

    // NEW: allowlist de mensajes sin firma
    static bool is_allowlisted_unsigned(uint32_t msgid);

    // NEW: derivación desde SS (HKDF) — declarada aquí si la usas desde varios .cpp
    void  derive_session_keys_from_ss(const uint8_t* ss, size_t ss_len,
                                      const uint8_t salt16[16]);

    // -------- Backend AEAD (ASCON) ----------
    bool aead_ready_ = false;
    bool aead_init_backend();
    bool aead_sizes(AP_AEAD_Sizes& out) const;
    bool aead_encrypt(uint8_t* c, size_t& clen,
                      const uint8_t* m, size_t mlen,
                      const uint8_t* ad, size_t adlen,
                      const uint8_t* npub,
                      const uint8_t* key);
    bool aead_decrypt(uint8_t* m, size_t& mlen,
                      const uint8_t* c, size_t clen,
                      const uint8_t* ad, size_t adlen,
                      const uint8_t* npub,
                      const uint8_t* key);

    // -------- Backend KEM (HQC) ----------
    bool hqc_ready_ = false;
    bool hqc_init_backend();
    typedef int (*hqc_enc_t)(uint8_t* ct, uint8_t* ss, const uint8_t* pk);
    hqc_enc_t hqc_enc_ = nullptr;

    // -------- Ensamblado de PK/CT ----------
    struct HqcRxBuf {
        uint64_t session_id = 0;
        uint32_t pk_len = 0;
        uint32_t ct_len = 0;
        uint8_t  version = 1;
        uint8_t  suite_id = 1; // 1=hqc-128
        uint8_t  flags = 0;
        uint8_t  salt[16] = {0};

        // NEW: guarda SS y CRCs para FINISH
        uint8_t  ss[64] = {0};     // tamaño HQC-128; ajusta si otro suite
        uint32_t pk_crc = 0;       // CRC32 de PK
        uint32_t ct_crc = 0;       // CRC32 de CT

        // Buffers dinámicos
        uint8_t* pk = nullptr;
        uint8_t* ct = nullptr;
        uint32_t pk_rcvd = 0;
        uint32_t ct_sent = 0;

        // MTU/ventana negociada
        uint16_t mtu = 220;
        uint8_t  window = 8;
        std::unordered_map<uint32_t, uint8_t> retries;
        uint8_t  max_retries = 3;

        uint32_t ct_chunks() const { return (ct_len + (uint32_t)mtu - 1U) / (uint32_t)mtu; }
        std::vector<uint8_t> ct_acked;

        void reset() {
            session_id = 0; pk_len = ct_len = 0;
            version = 1; suite_id = 1; flags = 0;
            memset(salt, 0, sizeof(salt));
            memset(ss,   0, sizeof(ss));     // NEW
            pk_crc = ct_crc = 0;             // NEW
            if (pk) { free(pk); pk = nullptr; }
            if (ct) { free(ct); ct = nullptr; }
            pk_rcvd = 0; ct_sent = 0;
            mtu = 220; window = 8;
            retries.clear();
            max_retries = 3;
            ct_acked.clear();
        }
        ~HqcRxBuf(){ reset(); }
    } hqc_;

    // -------- Parámetros/Gate ----------
    AP_Int8   _crypto_on;
    AP_Int8   _crypto_alg;
    AP_Int32  _crypto_ttl_ms;
    AP_Int16  _crypto_rate_pps;
    AP_Int8   _crypto_session;

    // -------- Estado runtime ----------
    CryptoSession  _sess;
    uint32_t       _rate_tokens = 0;
    uint32_t       _rate_last_ms = 0;

    // Envío de CT fragmentado y declaraciones
    void send_hqc_ct_chunks();
    void resend_ct_chunk_at(uint32_t off);
    void resend_ct_window(uint32_t base, uint32_t mask);
    void send_msg_raw(const mavlink_message_t& m);
    void nonce_from_seq(uint16_t seq, uint8_t out16[16]) const;
    void derive_session_key_from_ss(const uint8_t ss[32], const uint8_t salt16[16], uint8_t key16_out[16], uint8_t nonce_base16_out[16]);
    void send_hqc_status(uint8_t status, uint32_t value = 0, uint8_t detail = 0);

    // Hook de inicialización
    void crypto_init_if_needed();
};
