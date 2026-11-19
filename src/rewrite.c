/* rewrite.c —— 在 Binder Parcel 里定位 attestation 证书并等长替换 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include "attest.h"
#include "veil_cfg.h"

#define TAG "VeilTEE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static const uint8_t OID_KD[] = {
    0x06,0x0A,0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x01,0x11
};

typedef struct { uint8_t tag; const uint8_t *val; size_t len; size_t total; } tlv_t;

static int tlv_read(const uint8_t *p, size_t avail, tlv_t *o) {
    if (avail < 2) return -1;
    size_t i = 0;
    o->tag = p[i++];
    if ((o->tag & 0x1F) == 0x1F) {
        while (i < avail && (p[i] & 0x80)) i++;
        i++;
    }
    if (i >= avail) return -1;
    size_t l = p[i++];
    if (l & 0x80) {
        size_t n = l & 0x7F;
        if (!n || n > 4 || i + n > avail) return -1;
        l = 0;
        for (size_t k = 0; k < n; k++) l = (l << 8) | p[i++];
    }
    if (i + l > avail) return -1;
    o->val = p + i; o->len = l; o->total = i + l;
    return 0;
}

/* 从 leaf 里取公钥（65B）与 challenge */
static int leaf_extract(const uint8_t *cert, size_t len,
                        uint8_t pub65[65], uint8_t *challenge, size_t *clen) {
    tlv_t seq, tbs;
    if (tlv_read(cert, len, &seq) != 0 || seq.tag != 0x30) return -1;
    if (tlv_read(seq.val, seq.len, &tbs) != 0 || tbs.tag != 0x30) return -1;

    const uint8_t *p = tbs.val; size_t rem = tbs.len; tlv_t t;
    if (tlv_read(p, rem, &t) != 0) return -1;
    if (t.tag == 0xA0) { p += t.total; rem -= t.total; }
    for (int i = 0; i < 4; i++) {                    /* serial, sigalg, issuer, validity */
        if (tlv_read(p, rem, &t) != 0) return -1;
        p += t.total; rem -= t.total;
    }
    if (tlv_read(p, rem, &t) != 0 || t.tag != 0x30) return -1;   /* subject */
    p += t.total; rem -= t.total;
    /* SPKI */
    tlv_t spki;
    if (tlv_read(p, rem, &spki) != 0 || spki.tag != 0x30) return -1;
    {
        const uint8_t *q = spki.val; size_t r = spki.len; tlv_t alg, bits;
        if (tlv_read(q, r, &alg) != 0) return -1;
        q += alg.total; r -= alg.total;
        if (tlv_read(q, r, &bits) != 0 || bits.tag != 0x03) return -1;
        if (bits.len < 66 || bits.val[0] != 0x00) return -1;
        memcpy(pub65, bits.val + 1, 65);
    }
    p += spki.total; rem -= spki.total;

    /* 找 extensions [3] */
    const uint8_t *ext = NULL; size_t extlen = 0;
    while (rem >= 2) {
        if (tlv_read(p, rem, &t) != 0) break;
        if (t.tag == 0xA3) { ext = t.val; extlen = t.len; break; }
        p += t.total; rem -= t.total;
    }
    if (!ext) return -2;

    tlv_t list;
    if (tlv_read(ext, extlen, &list) != 0 || list.tag != 0x30) return -2;
    const uint8_t *q = list.val; size_t r = list.len;
    while (r >= 2) {
        tlv_t one;
        if (tlv_read(q, r, &one) != 0) break;
        if (one.tag == 0x30) {
            tlv_t oid, val;
            if (tlv_read(one.val, one.len, &oid) == 0 && oid.tag == 0x06 &&
                oid.len == 10 && memcmp(oid.val, OID_KD + 2, 10) == 0) {
                const uint8_t *vp = one.val + oid.total;
                size_t vr = one.len - oid.total;
                if (tlv_read(vp, vr, &val) == 0 && val.tag == 0x04) {
                    tlv_t kd;
                    if (tlv_read(val.val, val.len, &kd) == 0 && kd.tag == 0x30) {
                        const uint8_t *kp = kd.val; size_t kr = kd.len; tlv_t f;
                        /* version, secLevel, kmVersion, kmSecLevel, challenge */
                        for (int i = 0; i < 4; i++) {
                            if (tlv_read(kp, kr, &f) != 0) return -3;
                            kp += f.total; kr -= f.total;
                        }
                        if (tlv_read(kp, kr, &f) != 0 || f.tag != 0x04) return -3;
                        if (f.len > 64) f.len = 64;
                        memcpy(challenge, f.val, f.len);
                        *clen = f.len;
                        return 0;
                    }
                }
            }
        }
        q += one.total; r -= one.total;
    }
    return -3;
}

/* 在 buffer 里找出所有带 attestation OID 的证书区间 */
static int find_certs(const uint8_t *buf, size_t len,
                      size_t *off, size_t *clen, int max) {
    int found = 0;
    for (size_t i = 0; i + sizeof OID_KD < len && found < max; i++) {
        if (memcmp(buf + i, OID_KD, sizeof OID_KD) != 0) continue;
        size_t start = 0;
        for (size_t j = i; j > 0; j--) {
            if (buf[j] == 0x30 && buf[j + 1] == 0x82) { start = j; break; }
            if (buf[j] == 0x30 && buf[j + 1] == 0x81) { start = j; break; }
        }
        if (!start) continue;
        size_t total;
        if (buf[start + 1] == 0x82) total = (((size_t)buf[start + 2] << 8) | buf[start + 3]) + 4;
        else                        total = buf[start + 2] + 3;
        if (start + total > len) continue;
        off[found] = start; clen[found] = total; found++;
        i = start + total;
    }
    return found;
}

/* 等长替换：新证书不足则补未定义 tag 填充 */
static int replace_inplace(uint8_t *buf, size_t buf_len,
                           size_t off, size_t orig_len,
                           uint8_t *cert, size_t cert_len) {
    if (off + orig_len > buf_len) return -1;
    if (cert_len > orig_len) return -2;

    size_t pad = orig_len - cert_len;
    if (pad) {
        /* 解出外层 SEQUENCE 的内容长度，补上 pad */
        size_t hdr = (cert[1] & 0x80) ? 2 + (cert[1] & 0x7F) : 2;
        size_t inner = cert_len - hdr;
        size_t new_inner = inner + pad;
        if (cert[1] & 0x80) {
            size_t nb = cert[1] & 0x7F;
            for (size_t k = 0; k < nb; k++)
                cert[2 + k] = (uint8_t)(new_inner >> (8 * (nb - 1 - k)));
        } else {
            cert[1] = (uint8_t)new_inner;
        }
        memset(cert + cert_len, 0x00, pad);
        if (pad >= 2) { cert[cert_len] = 0x9F; cert[cert_len + 1] = 0x7F; }
    }
    memcpy(buf + off, cert, orig_len);
    return 0;
}

int veil_rewrite_reply(uint8_t *data, size_t size, uint32_t code, const veil_cfg *cfg) {
    if (!cfg || !cfg->enabled || !cfg->keybox_priv[0]) return 0;

    size_t off[8], cl[8];
    int n = find_certs(data, size, off, cl, 8);
    if (n <= 0) return 0;

    veil_trust_t tr;
    memset(&tr, 0, sizeof tr);
    if (veil_hex2bin(cfg->vb_key_hex, tr.vb_key, 32) != 0) memset(tr.vb_key, 0x11, 32);
    if (veil_hex2bin(cfg->vb_hash_hex, tr.vb_hash, 32) != 0) memset(tr.vb_hash, 0x22, 32);
    tr.device_locked  = cfg->device_locked;
    tr.boot_state     = cfg->boot_state;
    tr.security_level = cfg->security_level;
    tr.os_version     = cfg->os_version;
    snprintf(tr.patch_level, sizeof tr.patch_level, "%s", cfg->patch_level);

    for (int i = 0; i < n; i++) {
        uint8_t pub[65]; uint8_t ch[64]; size_t chlen = 0;
        if (leaf_extract(data + off[i], cl[i], pub, ch, &chlen) != 0) continue;

        uint8_t fresh[2048];
        int r = veil_attest_from_keybox(cfg->keybox_priv, cfg->keybox_cert,
                                        pub, ch, chlen, &tr, fresh, sizeof fresh);
        if (r < 0) { LOGI("build leaf failed %d", r); continue; }

        if (replace_inplace(data, size, off[i], cl[i], fresh, (size_t)r) == 0)
            LOGI("attestation rewritten (%zu bytes)", cl[i]);
    }
    return n;
}
