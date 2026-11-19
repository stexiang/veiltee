/* attest.h —— KeyAttestation 伪造：三绿 RootOfTrust */
#ifndef VEIL_ATTEST_H
#define VEIL_ATTEST_H
#include <stdint.h>
#include <stddef.h>
#include "p256.h"

typedef struct {
    uint8_t vb_key[32];       /* verifiedBootKey  = ro.boot.vbmeta.public_key_digest */
    uint8_t vb_hash[32];      /* verifiedBootHash = ro.boot.vbmeta.digest */
    int     device_locked;    /* 1 = locked      ← 第一绿 */
    int     boot_state;       /* 0 = Verified    ← 第二绿 */
    int     security_level;   /* 1 = TEE */
    int     os_version;       /* e.g. 16 */
    char    patch_level[16];  /* "2026-11-05" */
} veil_trust_t;

/* 解析 PEM 里的 EC 私钥（SEC1 或 PKCS#8），得到 d */
int veil_parse_ec_privkey(const char *pem, u256 *d);

/* 从 DER 证书里取出完整 subject SEQUENCE 的原始字节 */
int veil_cert_subject(const uint8_t *cert, size_t len,
                      const uint8_t **out, size_t *out_len);

/* 构造 leaf 证书：
 *   issuer/subject 复用 keybox 证书的 subject，
 *   pubkey 用 attestation 公钥，
 *   KeyDescription 里写入三绿 RootOfTrust。
 * out 需要至少 2048 字节；返回实际长度，<0 失败。 */
int veil_build_leaf(const uint8_t *subject, size_t subject_len,
                    const uint8_t pub65[65],
                    const uint8_t *challenge, size_t challenge_len,
                    const veil_trust_t *trust,
                    const u256 *keybox_d,
                    uint8_t *out, size_t cap);

/* 便利函数：直接从 keybox PEM（私钥+证书）生成 leaf */
int veil_attest_from_keybox(const char *priv_pem, const char *cert_pem,
                            const uint8_t att_pub65[65],
                            const uint8_t *challenge, size_t challenge_len,
                            const veil_trust_t *trust,
                            uint8_t *out, size_t cap);

#endif
