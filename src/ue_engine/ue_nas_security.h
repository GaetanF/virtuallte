#ifndef UE_NAS_SECURITY_H
#define UE_NAS_SECURITY_H

/*
 * ue_nas_security - NAS security: Milenage, KDF, integrity, ciphering.
 *
 * Implements:
 *   - Milenage f1-f5* (3GPP TS 35.205-208) for 5G-AKA
 *   - Key derivation: CK,IK → KAUSF → KSEAF → KAMF → KNASint,KNASenc
 *   - NAS integrity protection (NIA0 null, NIA2 AES-CMAC)
 *   - NAS ciphering (NEA0 null, NEA2 AES-CTR)
 *   - NAS security context management
 *   - Security header wrap/unwrap
 *
 * UERANSIM anchor:
 *   - src/ext/crypt-ext/milenage.c    : Milenage algorithm
 *   - src/lib/crypt/crypt.cpp         : KDF (HMAC-SHA-256)
 *   - src/ue/nas/keys.cpp             : Key derivation chain
 *   - src/ue/nas/enc.cpp              : NAS encrypt/decrypt
 *   - src/lib/crypt/mac.cpp           : EIA2 (AES-CMAC)
 *   - src/lib/crypt/eea2.cpp          : EEA2 (AES-128-CTR)
 *
 * Wire format: TS 24.501, TS 33.501
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --- Milenage --- */

/*
 * Milenage result from f1-f5*.
 */
struct ue_milenage_result {
    uint8_t res[8];       /* f2: RES (8 bytes) */
    uint8_t ck[16];       /* f3: CK (16 bytes) */
    uint8_t ik[16];       /* f4: IK (16 bytes) */
    uint8_t ak[6];        /* f5: AK (6 bytes) */
    uint8_t ak_star[6];   /* f5*: AK* (6 bytes) */
    uint8_t mac_a[8];     /* f1: MAC-A (8 bytes) */
    uint8_t mac_s[8];     /* f1*: MAC-S (8 bytes) */
};

/*
 * Compute OPc from OP and K.
 * opc: output (16 bytes)
 */
int ue_milenage_opc(uint8_t *opc, const uint8_t *k, const uint8_t *op);

/*
 * Run full Milenage computation.
 * opc: pre-computed OPc (16 bytes), or NULL to use op
 * k: subscriber key K (16 bytes)
 * rand: network random challenge RAND (16 bytes)
 * sqn: sequence number SQN (6 bytes)
 * amf: authentication management field AMF (2 bytes)
 */
int ue_milenage_compute(const uint8_t *opc, const uint8_t *k,
                        const uint8_t *rand, const uint8_t *sqn,
                        const uint8_t *amf,
                        struct ue_milenage_result *out);

/* --- Key Derivation --- */

/*
 * 5G key derivation chain.
 * All keys derived using HMAC-SHA-256 based KDF (TS 33.501 Annex A).
 */
struct ue_nas_keys {
    uint8_t kausf[32];
    uint8_t kseaf[32];
    uint8_t kamf[32];
    uint8_t knas_int[16];   /* NAS integrity key */
    uint8_t knas_enc[16];   /* NAS ciphering key */
    uint8_t res_star[16];   /* RES* for 5G-AKA */
};

/*
 * Derive the full 5G key chain from Milenage outputs.
 *
 * ck, ik: from Milenage f3/f4 (16 bytes each)
 * ak: from Milenage f5 (6 bytes)
 * rand: RAND from Authentication Request (16 bytes)
 * res: RES from Milenage f2 (8 bytes)
 * sqn: SQN (6 bytes)
 * snn: Serving Network Name (e.g. "5G:mnc001.mcc001.3gppnetwork.org")
 * supi: SUPI string (e.g. "imsi-001010000000001")
 * abba: ABBA parameter (2 bytes, from SMC or default 0x0000)
 * int_alg_id: selected integrity algorithm (0=NIA0, 1=NIA1, 2=NIA2)
 * enc_alg_id: selected ciphering algorithm (0=NEA0, 1=NEA1, 2=NEA2)
 */
int ue_nas_derive_keys(const uint8_t *ck, const uint8_t *ik,
                       const uint8_t *ak, const uint8_t *rand,
                       const uint8_t *res, const uint8_t *sqn,
                       const char *snn, const char *supi,
                       const uint8_t *abba, size_t abba_len,
                       uint8_t int_alg_id, uint8_t enc_alg_id,
                       struct ue_nas_keys *out);

/*
 * Derive NAS keys only from an existing KAMF.
 *
 * This matches the NAS algorithm selection step used during SMC handling,
 * where KNASint/KNASenc are derived from the context KAMF and selected algos.
 */
int ue_nas_derive_knas_from_kamf(const uint8_t *kamf,
                                 uint8_t int_alg_id,
                                 uint8_t enc_alg_id,
                                 uint8_t *knas_int,
                                 uint8_t *knas_enc);

/* --- NAS Security Context --- */

/*
 * NAS COUNT: overflow(16) + sqn(8) → 32-bit COUNT value.
 */
struct ue_nas_count {
    uint16_t overflow;
    uint8_t sqn;
};

static inline uint32_t ue_nas_count_value(const struct ue_nas_count *c)
{
    return ((uint32_t)c->overflow << 8) | (uint32_t)c->sqn;
}

static inline void ue_nas_count_increment(struct ue_nas_count *c)
{
    c->sqn++;
    if (c->sqn == 0)
        c->overflow++;
}

/*
 * NAS integrity algorithm IDs.
 */
enum ue_nas_integrity_alg {
    UE_NIA0 = 0,   /* null integrity */
    UE_NIA1 = 1,   /* 128-SNOW3G (not implemented) */
    UE_NIA2 = 2,   /* 128-AES-CMAC */
};

/*
 * NAS ciphering algorithm IDs.
 */
enum ue_nas_ciphering_alg {
    UE_NEA0 = 0,   /* null ciphering */
    UE_NEA1 = 1,   /* 128-SNOW3G (not implemented) */
    UE_NEA2 = 2,   /* 128-AES-CTR */
};

/*
 * Full NAS security context.
 */
struct ue_nas_security_ctx {
    bool active;                      /* security context established */

    struct ue_nas_keys keys;
    enum ue_nas_integrity_alg int_alg;
    enum ue_nas_ciphering_alg enc_alg;

    struct ue_nas_count ul_count;     /* uplink NAS COUNT */
    struct ue_nas_count dl_count;     /* downlink NAS COUNT */

    uint8_t bearer;                   /* 1 = 3GPP access */
    uint8_t ngksi;                    /* ngKSI (0-6, 7 = no key) */

    /* Milenage state preserved for key derivation during AKA */
    struct ue_milenage_result milenage;
    uint8_t rand[16];                 /* RAND from last AuthRequest */
    uint8_t sqn_xor_ak[6];           /* SQN XOR AK from AUTN */
    uint8_t abba[16];                /* ABBA from AuthRequest */
    uint8_t abba_len;
};

/* Parsed NAS security envelope header (downlink). */
struct ue_nas_sec_header_info {
    uint8_t epd;
    uint8_t sht;
    uint32_t mac;
    uint8_t sqn;
};

/* --- NAS integrity/ciphering --- */

/*
 * Compute NAS MAC (integrity protection).
 * Returns 32-bit MAC value.
 */
uint32_t ue_nas_compute_mac(enum ue_nas_integrity_alg alg,
                            uint32_t count, uint8_t bearer,
                            uint8_t direction,
                            const uint8_t *key,
                            const uint8_t *msg, size_t msg_len);

/*
 * Apply NAS ciphering (encrypt or decrypt, symmetric).
 * Operates in-place on data[].
 */
int ue_nas_cipher(enum ue_nas_ciphering_alg alg,
                  uint32_t count, uint8_t bearer,
                  uint8_t direction,
                  const uint8_t *key,
                  uint8_t *data, size_t data_len);

/* --- Security header wrap/unwrap --- */

/*
 * Wrap a plain NAS message with security header.
 *
 * Output format (TS 24.501 §9.1):
 *   EPD(1) + SHT(1) + MAC(4) + SQN(1) + plain NAS message
 *
 * buf: output buffer
 * buf_len: output buffer size
 * ctx: NAS security context (ul_count will be incremented)
 * plain: plain NAS message
 * plain_len: plain message length
 *
 * Returns total length of security-protected message, or -1 on error.
 */
int ue_nas_security_protect(uint8_t *buf, size_t buf_len,
                            struct ue_nas_security_ctx *ctx,
                            const uint8_t *plain, size_t plain_len);

/*
 * Wrap a plain NAS message with security header using explicit SHT.
 *
 * Supported SHT values:
 *   0x01 INTEGRITY_PROTECTED
 *   0x02 INTEGRITY_PROTECTED_CIPHERED
 *   0x03 INTEGRITY_PROTECTED_NEW_CTX
 *   0x04 INTEGRITY_PROTECTED_CIPHERED_NEW_CTX
 */
int ue_nas_security_protect_with_sht(uint8_t *buf, size_t buf_len,
                                     struct ue_nas_security_ctx *ctx,
                                     const uint8_t *plain, size_t plain_len,
                                     uint8_t sht);

/*
 * Unwrap a security-protected NAS message.
 *
 * Verifies integrity, deciphers, and returns pointer to the plain NAS message.
 *
 * data: input security-protected message
 * len: input length
 * ctx: NAS security context (dl_count will be updated)
 * out_plain: set to pointer within data[] to the plain NAS message
 * out_plain_len: set to plain NAS message length
 *
 * Returns 0 on success, -1 on integrity failure or error.
 */
int ue_nas_security_unprotect(uint8_t *data, size_t len,
                              struct ue_nas_security_ctx *ctx,
                              const uint8_t **out_plain, size_t *out_plain_len);

/*
 * Parse-only NAS security envelope unwrapping.
 *
 * This helper extracts security header fields and returns the inner NAS payload
 * without MAC verification and without deciphering. It is intended as a
 * temporary bridge for handling messages with new NAS security context before
 * full verification wiring is completed.
 */
int ue_nas_security_unwrap_parse_only(const uint8_t *data, size_t len,
                                      struct ue_nas_sec_header_info *hdr,
                                      const uint8_t **out_inner,
                                      size_t *out_inner_len);

/* --- Crypto primitives (used internally, exposed for testing) --- */

/*
 * AES-128 ECB encrypt a single 16-byte block.
 */
void ue_aes128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);

/*
 * AES-CMAC (RFC 4493) — compute 16-byte MAC.
 */
void ue_aes_cmac(const uint8_t *key, const uint8_t *msg, size_t msg_len,
                 uint8_t *mac);

/*
 * HMAC-SHA-256.
 */
void ue_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t *out);

/*
 * 3GPP KDF (TS 33.220): HMAC-SHA-256(key, FC || P0 || L0 || P1 || L1 || ...)
 * out: 32 bytes
 */
void ue_3gpp_kdf(const uint8_t *key, size_t key_len,
                 uint8_t fc,
                 const uint8_t *p0, uint16_t l0,
                 const uint8_t *p1, uint16_t l1,
                 uint8_t *out);

#endif
