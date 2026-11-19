/* attest.c —— 构造三绿 attestation 证书（零依赖） */
#include "attest.h"
#include "der.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#define OID_ATTEST { 0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x01,0x11 }
static const uint8_t OID_KD[]   = OID_ATTEST;
static const uint8_t OID_ECDSA[]= { 0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02 };
static const uint8_t OID_ECPUB[]= { 0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01 };
static const uint8_t OID_P256[] = { 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };

/* ---------------- TLV 解析 ---------------- */
typedef struct { uint8_t tag; const uint8_t *val; size_t len; size_t total; } tlv_t;

static int tlv_read(const uint8_t *p, size_t avail, tlv_t *o) {
    if (avail < 2) return -1;
    size_t i = 0;
    o->tag = p[i++];
    if ((o->tag & 0x1F) == 0x1F) {            /* high tag number */
        while (i < avail && (p[i] & 0x80)) i++;
        i++;
    }
    if (i >= avail) return -1;
    size_t l = p[i++];
    if (l & 0x80) {
        size_t n = l & 0x7F;
        if (n == 0 || n > 4 || i + n > avail) return -1;
        l = 0;
        for (size_t k = 0; k < n; k++) l = (l << 8) | p[i++];
    }
    if (i + l > avail) return -1;
    o->val = p + i;
    o->len = l;
    o->total = i + l;
    return 0;
}

/* ---------------- PEM / base64 ---------------- */
static int b64v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int pem_body(const char *pem, uint8_t *out, size_t cap, size_t *out_len) {
    const char *b = strstr(pem, "-----BEGIN");
    if (!b) return -1;
    b = strchr(b, '\n');
    if (!b) return -1;
    b++;
    const char *e = strstr(b, "-----END");
    if (!e) return -1;

    size_t n = 0, acc = 0; int bits = 0;
    for (const char *p = b; p < e; p++) {
        if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') continue;
        if (*p == '=') break;                       /* base64 padding */
        int v = b64v(*p);
        if (v < 0) return -1;
        acc = (acc << 6) | (size_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n < cap) out[n] = (uint8_t)((acc >> bits) & 0xFF);
            n++;
        }
    }
    *out_len = n;
    return 0;
}

/* ---------------- 私钥解析 ---------------- */
int veil_parse_ec_privkey(const char *pem, u256 *d) {
    uint8_t der[512]; size_t der_len = 0;
    if (pem_body(pem, der, sizeof der, &der_len) != 0) return -1;

    tlv_t seq;
    if (tlv_read(der, der_len, &seq) != 0 || seq.tag != 0x30) return -1;

    const uint8_t *p = seq.val; size_t rem = seq.len;
    tlv_t t;

    /* 跳过 version */
    if (tlv_read(p, rem, &t) != 0) return -1;
    /* PKCS#8 检测：第 2 个元素是 SEQUENCE（AlgorithmIdentifier） */
    if (t.tag == 0x02) {
        const uint8_t *q = p + t.total; size_t r = rem - t.total;
        tlv_t second;
        if (tlv_read(q, r, &second) == 0 && second.tag == 0x30) {
            /* PKCS#8：后面是 OCTET STRING，里面再套 SEC1 */
            const uint8_t *q2 = q + second.total; size_t r2 = r - second.total;
            tlv_t oct;
            if (tlv_read(q2, r2, &oct) == 0 && oct.tag == 0x04) {
                tlv_t inner;
                if (tlv_read(oct.val, oct.len, &inner) != 0 || inner.tag != 0x30) return -1;
                p = inner.val; rem = inner.len;
                if (tlv_read(p, rem, &t) != 0) return -1;      /* version */
            }
        }
    }
    p += t.total; rem -= t.total;
    if (tlv_read(p, rem, &t) != 0 || t.tag != 0x04 || t.len != 32) return -1;
    u256_from_be(d, t.val);
    return 0;
}

/* ---------------- 证书 subject ---------------- */
int veil_cert_subject(const uint8_t *cert, size_t len,
                      const uint8_t **out, size_t *out_len) {
    tlv_t seq;
    if (tlv_read(cert, len, &seq) != 0 || seq.tag != 0x30) return -1;
    tlv_t tbs;
    if (tlv_read(seq.val, seq.len, &tbs) != 0 || tbs.tag != 0x30) return -1;

    const uint8_t *p = tbs.val; size_t rem = tbs.len;
    tlv_t t;
    /* [0] version（可选，0xA0） */
    if (tlv_read(p, rem, &t) != 0) return -1;
    if (t.tag == 0xA0) { p += t.total; rem -= t.total; }
    /* serial, sigalg, issuer, validity, subject */
    for (int i = 0; i < 4; i++) {
        if (tlv_read(p, rem, &t) != 0) return -1;
        p += t.total; rem -= t.total;
    }
    if (tlv_read(p, rem, &t) != 0) return -1;      /* subject */
    const uint8_t *start = p;
    *out = start;
    *out_len = t.total;
    return 0;
}

/* ---------------- KeyDescription ---------------- */
static size_t build_root_of_trust(const veil_trust_t *t, uint8_t *out) {
    uint8_t inner[160]; size_t n = 0;
    n = der_octets(inner, n, t->vb_key, 32);
    n = der_bool(inner, n, t->device_locked);
    /* ENUMERATED verifiedBootState */
    {
        uint8_t b = (uint8_t)t->boot_state;
        n = der_put(inner, n, 0x0A, &b, 1);
    }
    n = der_octets(inner, n, t->vb_hash, 32);

    uint8_t seq[200]; size_t sn = 0;
    sn = der_put(seq, sn, 0x30, inner, n);
    return der_ctx(out, 0, 704, seq, sn);
}

static size_t build_key_description(const veil_trust_t *t,
                                    const uint8_t *challenge, size_t clen,
                                    uint8_t *out, size_t cap) {
    uint8_t body[1024]; size_t n = 0;

    n = der_uint64(body, n, 300);                       /* attestationVersion */
    { uint8_t b = (uint8_t)t->security_level;
      n = der_put(body, n, 0x0A, &b, 1); }              /* SecurityLevel */
    n = der_uint64(body, n, 300);                       /* keymasterVersion */
    { uint8_t b = (uint8_t)t->security_level;
      n = der_put(body, n, 0x0A, &b, 1); }
    n = der_octets(body, n, challenge, clen);           /* challenge */
    n = der_octets(body, n, (const uint8_t *)"", 0);    /* uniqueId */

    /* softwareEnforced: osVersion(705) + osPatchLevel(706) */
    {
        uint8_t sw[96]; size_t sn = 0;
        uint8_t iv[16]; size_t il = 0;
        il = der_uint64(iv, 0, (uint64_t)t->os_version * 10000);
        sn = der_ctx(sw, sn, 705, iv, il);
        if (t->patch_level[0]) {
            int y = 0, mo = 0;
            if (sscanf(t->patch_level, "%4d-%2d", &y, &mo) == 2) {
                il = der_uint64(iv, 0, (uint64_t)y * 100 + mo);
                sn = der_ctx(sw, sn, 706, iv, il);
            }
        }
        n = der_put(body, n, 0x30, sw, sn);
    }

    /* teeEnforced: RootOfTrust + 常规 tag */
    {
        uint8_t te[512]; size_t tn = 0;
        tn = build_root_of_trust(t, te);

        /* purpose: SIGN(2) */
        { uint8_t v[] = { 0x0A, 0x01, 0x02 }; tn = der_ctx(te, tn, 1, v, 3); }
        /* algorithm: EC(3) */
        { uint8_t v[] = { 0x0A, 0x01, 0x03 }; tn = der_ctx(te, tn, 2, v, 3); }
        /* ecCurve: P-256(1) */
        { uint8_t v[] = { 0x0A, 0x01, 0x01 }; tn = der_ctx(te, tn, 10, v, 3); }
        /* origin: GENERATED(0) */
        { uint8_t v[] = { 0x0A, 0x01, 0x00 }; tn = der_ctx(te, tn, 702, v, 3); }
        /* attestationApplicationId(709) */
        { uint8_t a[8]; size_t an = der_octets(a, 0, (const uint8_t *)"", 0);
          uint8_t s2[16]; size_t s2n = der_put(s2, 0, 0x30, a, an);
          tn = der_ctx(te, tn, 709, s2, s2n); }

        n = der_put(body, n, 0x30, te, tn);
    }

    if (n + 8 > cap) return 0;
    size_t total = der_put(out, 0, 0x30, body, n);
    return total;
}

/* ---------------- 证书构造 ---------------- */
static size_t utc_time(uint8_t *o, time_t t) {
    struct tm tm;
    gmtime_r(&t, &tm);
    char s[16];
    snprintf(s, sizeof s, "%02d%02d%02d%02d%02d%02dZ",
             (tm.tm_year + 1900) % 100, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    return der_put(o, 0, 0x17, (const uint8_t *)s, 13);
}

int veil_build_leaf(const uint8_t *subject, size_t subject_len,
                    const uint8_t pub65[65],
                    const uint8_t *challenge, size_t challenge_len,
                    const veil_trust_t *trust,
                    const u256 *keybox_d,
                    uint8_t *out, size_t cap) {
    uint8_t kd[1024];
    size_t kd_len = build_key_description(trust, challenge, challenge_len, kd, sizeof kd);
    if (!kd_len) return -1;

    uint8_t tbs[2048]; size_t n = 0;

    /* version [0] { INTEGER 2 } */
    { uint8_t v[8]; size_t vn = der_uint64(v, 0, 2);
      n = der_ctx_low(tbs, n, 0, v, vn); }
    /* serial */
    { uint8_t s[20];
      for (int i = 0; i < 20; i++) s[i] = (uint8_t)(0x10 + i * 7);
      n = der_put(tbs, n, 0x02, s, 20); }
    /* signature AlgorithmIdentifier */
    { uint8_t a[16]; size_t an = der_oid(a, 0, OID_ECDSA, sizeof OID_ECDSA);
      n = der_put(tbs, n, 0x30, a, an); }
    /* issuer = subject（复制原始 DER，包含 0x30 外壳） */
    { if (n + subject_len > sizeof tbs) return -1;
      memcpy(tbs + n, subject, subject_len); n += subject_len; }
    /* validity */
    { uint8_t v[64]; size_t vn = 0;
      time_t now = time(NULL);
      vn = utc_time(v, now - 86400L);
      vn += utc_time(v + vn, now + 86400L * 3650);
      n = der_put(tbs, n, 0x30, v, vn); }
    /* subject */
    { if (n + subject_len > sizeof tbs) return -1;
      memcpy(tbs + n, subject, subject_len); n += subject_len; }
    /* SPKI */
    { uint8_t spki[128]; size_t sn = 0;
      uint8_t alg[32]; size_t an = 0;
      an = der_oid(alg, an, OID_ECPUB, sizeof OID_ECPUB);
      an = der_oid(alg, an, OID_P256, sizeof OID_P256);
      uint8_t algs[32]; size_t algn = der_put(algs, 0, 0x30, alg, an);
      memcpy(spki, algs, algn); sn = algn;
      sn = der_bitstring(spki, sn, pub65, 65);
      uint8_t spkis[160]; size_t spkisn = der_put(spkis, 0, 0x30, spki, sn);
      if (n + spkisn > sizeof tbs) return -1;
      memcpy(tbs + n, spkis, spkisn); n += spkisn; }

    /* extensions [3] { SEQUENCE { Extension } } */
    { uint8_t one[1300]; size_t on = 0;
      on = der_oid(one, on, OID_KD, sizeof OID_KD);
      on = der_octets(one, on, kd, kd_len);
      uint8_t onew[1320]; size_t onw = der_put(onew, 0, 0x30, one, on);   /* Extension */
      uint8_t extseq[1350]; size_t esn = der_put(extseq, 0, 0x30, onew, onw); /* SEQUENCE OF */
      n = der_ctx_low(tbs, n, 3, extseq, esn); }

    /* TBS 外层 */
    uint8_t tbs_der[2048];
    size_t tbs_len = der_put(tbs_der, 0, 0x30, tbs, n);

    /* 签名 */
    uint8_t hash[32];
    sha256(tbs_der, tbs_len, hash);
    uint8_t r[32], s[32];
    if (p256_ecdsa_sign(keybox_d, hash, r, s) != 0) return -1;

    /* ECDSA-Sig-Value */
    uint8_t sigv[80]; size_t sn = 0;
    sn = der_int(sigv, sn, r, 32);
    sn = der_int(sigv, sn, s, 32);
    uint8_t sigseq[96]; size_t ssn = der_put(sigseq, 0, 0x30, sigv, sn);

    /* Certificate */
    uint8_t body[2400]; size_t bn = 0;
    memcpy(body, tbs_der, tbs_len); bn = tbs_len;
    { uint8_t a[16]; size_t an = der_oid(a, 0, OID_ECDSA, sizeof OID_ECDSA);
      uint8_t as[32]; size_t asn = der_put(as, 0, 0x30, a, an);
      memcpy(body + bn, as, asn); bn += asn; }
    bn = der_bitstring(body, bn, sigseq, ssn);

    size_t total = der_put(out, 0, 0x30, body, bn);
    return (int)total;
}

int veil_attest_from_keybox(const char *priv_pem, const char *cert_pem,
                            const uint8_t att_pub65[65],
                            const uint8_t *challenge, size_t challenge_len,
                            const veil_trust_t *trust,
                            uint8_t *out, size_t cap) {
    u256 d;
    if (veil_parse_ec_privkey(priv_pem, &d) != 0) return -1;

    uint8_t cert[2048]; size_t cert_len = 0;
    if (pem_body(cert_pem, cert, sizeof cert, &cert_len) != 0) return -2;

    const uint8_t *subj = NULL; size_t subj_len = 0;
    if (veil_cert_subject(cert, cert_len, &subj, &subj_len) != 0) return -3;

    return veil_build_leaf(subj, subj_len, att_pub65, challenge, challenge_len,
                           trust, &d, out, cap);
}
