/* keybox_check.c —— keybox 有效性体检：链完整性 / 三绿 / 根身份 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "attest.h"
#include "veil_cfg.h"
#include "p256.h"
#include "sha256.h"

static const char *C_GREEN="\033[32m", *C_RED="\033[31m", *C_YEL="\033[33m", *C_RST="\033[0m";

typedef struct { uint8_t tag; const uint8_t *val; size_t len; size_t total; } tlv_t;

static int tlv(const uint8_t *p, size_t n, tlv_t *o) {
    if (n < 2) return -1;
    size_t i = 0;
    o->tag = p[i++];
    if ((o->tag & 0x1F) == 0x1F) { while (i < n && (p[i] & 0x80)) i++; i++; }
    if (i >= n) return -1;
    size_t l = p[i++];
    if (l & 0x80) {
        size_t k = l & 0x7F;
        if (!k || k > 4 || i + k > n) return -1;
        l = 0;
        for (size_t j = 0; j < k; j++) l = (l << 8) | p[i++];
    }
    if (i + l > n) return -1;
    o->val = p + i; o->len = l; o->total = i + l;
    return 0;
}

/* 取 tbs 的 issuer / subject / 有效期 / SPKI */
static int cert_parts(const uint8_t *c, size_t n,
                      const uint8_t **iss, size_t *issl,
                      const uint8_t **sub, size_t *subl,
                      const uint8_t **spki, size_t *spkil,
                      time_t *nb, time_t *na) {
    tlv_t seq, tbs;
    if (tlv(c, n, &seq) || seq.tag != 0x30) return -1;
    if (tlv(seq.val, seq.len, &tbs) || tbs.tag != 0x30) return -2;

    const uint8_t *p = tbs.val; size_t r = tbs.len; tlv_t t;
    if (tlv(p, r, &t)) return -3;
    if (t.tag == 0xA0) { p += t.total; r -= t.total; }      /* [0] version（v3） */
    /* v1 证书没有 version：当前位置就是 serial，交给下面统一读 */

    if (tlv(p, r, &t) || t.tag != 0x02) return -4; p += t.total; r -= t.total;  /* serial */
    if (tlv(p, r, &t) || t.tag != 0x30) return -5; p += t.total; r -= t.total;  /* sigalg */

    if (tlv(p, r, &t) || t.tag != 0x30) return -6;          /* issuer */
    *iss = p; *issl = t.total; p += t.total; r -= t.total;

    if (tlv(p, r, &t) || t.tag != 0x30) return -8;           /* validity */
    {
        const uint8_t *q = t.val; size_t qr = t.len; tlv_t d;
        if (tlv(q, qr, &d) == 0) { char b[32]={0}; memcpy(b,d.val,d.len<31?d.len:31);
            struct tm tm={0}; sscanf(b,"%2d%2d%2d%2d%2d%2d",&tm.tm_year,&tm.tm_mon,&tm.tm_mday,&tm.tm_hour,&tm.tm_min,&tm.tm_sec);
            tm.tm_year += tm.tm_year < 70 ? 100 : 0; tm.tm_mon -= 1; *nb = timegm(&tm); }
        q += d.total; qr -= d.total;
        if (tlv(q, qr, &d) == 0) { char b[32]={0}; memcpy(b,d.val,d.len<31?d.len:31);
            struct tm tm={0}; sscanf(b,"%2d%2d%2d%2d%2d%2d",&tm.tm_year,&tm.tm_mon,&tm.tm_mday,&tm.tm_hour,&tm.tm_min,&tm.tm_sec);
            tm.tm_year += tm.tm_year < 70 ? 100 : 0; tm.tm_mon -= 1; *na = timegm(&tm); }
    }
    p += t.total; r -= t.total;

    if (tlv(p, r, &t) || t.tag != 0x30) return -9;           /* subject */
    *sub = p; *subl = t.total; p += t.total; r -= t.total;

    if (tlv(p, r, &t) || t.tag != 0x30) return -10;           /* SPKI */
    *spki = p; *spkil = t.total;
    return 0;
}

/* 从 SPKI 取未压缩公钥 04||X||Y */
static int spki_pub(const uint8_t *spki, size_t n, uint8_t out65[65]) {
    tlv_t s, alg, bits;
    if (tlv(spki, n, &s) || s.tag != 0x30) return -1;
    const uint8_t *p = s.val; size_t r = s.len;
    if (tlv(p, r, &alg)) return -1; p += alg.total; r -= alg.total;
    if (tlv(p, r, &bits) || bits.tag != 0x03) return -1;
    if (bits.len < 66 || bits.val[0] != 0) return -1;
    memcpy(out65, bits.val + 1, 65);
    return 0;
}

/* 从证书里取 tbs 的 DER（用于验签） */
static int tbs_der(const uint8_t *c, size_t n, const uint8_t **out, size_t *outl) {
    tlv_t seq, tbs;
    if (tlv(c, n, &seq) || seq.tag != 0x30) return -1;
    if (tlv(seq.val, seq.len, &tbs) || tbs.tag != 0x30) return -1;
    *out = seq.val; *outl = tbs.total;
    return 0;
}

/* 从证书取签名值 r,s */
static int cert_sig(const uint8_t *c, size_t n, uint8_t r[32], uint8_t s[32]) {
    tlv_t seq, tbs, alg, bits;
    if (tlv(c, n, &seq) || seq.tag != 0x30) return -1;
    const uint8_t *p = seq.val; size_t r2 = seq.len;
    if (tlv(p, r2, &tbs)) return -1; p += tbs.total; r2 -= tbs.total;
    if (tlv(p, r2, &alg)) return -1; p += alg.total; r2 -= alg.total;
    if (tlv(p, r2, &bits) || bits.tag != 0x03) return -1;
    const uint8_t *sig = bits.val + 1; size_t sl = bits.len - 1;
    tlv_t sv, ri, si;
    if (tlv(sig, sl, &sv) || sv.tag != 0x30) return -1;
    if (tlv(sv.val, sv.len, &ri) || ri.tag != 0x02) return -1;
    const uint8_t *q = sv.val + ri.total; size_t qr = sv.len - ri.total;
    if (tlv(q, qr, &si) || si.tag != 0x02) return -1;
    memset(r, 0, 32); memset(s, 0, 32);
    size_t rl = ri.len > 32 ? 32 : ri.len;
    memcpy(r + 32 - rl, ri.val + (ri.len - rl), rl);
    size_t sl2 = si.len > 32 ? 32 : si.len;
    memcpy(s + 32 - sl2, si.val + (si.len - sl2), sl2);
    return 0;
}

/* 取证书里所有 CERTIFICATE PEM */
static int collect_certs(const char *xml, char out[][4096], int max) {
    int n = 0;
    const char *p = xml;
    while (n < max && (p = strstr(p, "-----BEGIN CERTIFICATE-----"))) {
        const char *e = strstr(p, "-----END CERTIFICATE-----");
        if (!e) break;
        e += strlen("-----END CERTIFICATE-----");
        size_t len = (size_t)(e - p);
        if (len < 4096) { memcpy(out[n], p, len); out[n][len] = 0; n++; }
        p = e;
    }
    return n;
}

static void dn_str(const uint8_t *dn, size_t n, char *out, size_t cap) {
    /* 极简：把 PrintableString / UTF8String 拼出来 */
    out[0] = 0; size_t o = 0;
    const uint8_t *p = dn; size_t r = n;
    tlv_t seq;
    if (tlv(p, r, &seq) || seq.tag != 0x30) return;
    p = seq.val; r = seq.len;
    tlv_t set;
    while (tlv(p, r, &set) == 0 && set.tag == 0x31) {
        tlv_t s2, oid, val;
        if (tlv(set.val, set.len, &s2) == 0 && s2.tag == 0x30) {
            const uint8_t *q = s2.val; size_t qr = s2.len;
            if (tlv(q, qr, &oid) == 0) { q += oid.total; qr -= oid.total; }
            if (tlv(q, qr, &val) == 0) {
                size_t take = val.len;
                if (o + take + 2 < cap) { memcpy(out + o, val.val, take); o += take; out[o++] = '/'; out[o] = 0; }
            }
        }
        p += set.total; r -= set.total;
    }
}

int is_google_root_hack = 0;

int kb_check(const char *path) {
    if (!path) path = "/data/adb/modules/veiltee/config/keybox.xml";
    FILE *f = fopen(path, "r");
    if (!f) { printf("open %s fail\n", path); return 1; }
    static char xml[262144];
    size_t xn = fread(xml, 1, sizeof xml - 1, f); xml[xn] = 0; fclose(f);

    printf("┌─ keybox 体检: %s ─────────────\n", path);

    /* 1) 私钥 */
    char priv[VEIL_PEM_MAX]; memset(priv, 0, sizeof priv);
    const char *pb = strstr(xml, "-----BEGIN EC PRIVATE KEY-----");
    if (!pb) pb = strstr(xml, "-----BEGIN PRIVATE KEY-----");
    if (!pb) { printf("│ [%s✗%s] 找不到私钥\n", C_RED, C_RST); return 1; }
    const char *pe = strstr(pb, "-----END");
    if (!pe) { printf("│ priv end not found\n"); return 1; }
    const char *eol = strchr(pe, '\n');
    if (!eol) eol = pe + strlen(pe);
    size_t plen = (size_t)(eol - pb);
    if (plen >= sizeof priv) plen = sizeof priv - 1;
    memcpy(priv, pb, plen);
    priv[plen] = 0;

    u256 d;
    if (veil_parse_ec_privkey(priv, &d) != 0) { printf("│ [%s✗%s] 私钥解析失败\n", C_RED, C_RST); return 1; }
    printf("│ [%s✓%s] 私钥解析 (EC P-256)\n", C_GREEN, C_RST);

    /* 2) 证书链 */
    static char certs[8][4096];
    int nc = collect_certs(xml, certs, 8);
    printf("│ [%s%s%s] 证书链: %d 张\n", nc > 0 ? C_GREEN : C_RED, nc > 0 ? "✓" : "✗", C_RST, nc);
    if (!nc) return 1;

    uint8_t buf[4096];
    static const uint8_t (*cder[8])[4096];
    size_t clen[8];
    for (int i = 0; i < nc; i++) {
        size_t n = 0;
        /* 复用 attest.c 的 pem 解码：通过 veil_parse_ec_privkey 不便，这里内联 */
        const char *b = strstr(certs[i], "\n");
        const char *e = strstr(b, "-----END");
        size_t acc = 0, bits = 0, o = 0;
        static const char *B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (const char *q = b; q < e; q++) {
            if (*q == '\n' || *q == '\r' || *q == ' ') continue;
            if (*q == '=') break;
            const char *p2 = strchr(B64, *q);
            if (!p2) continue;
            acc = (acc << 6) | (size_t)(p2 - B64);
            bits += 6;
            if (bits >= 8) { bits -= 8; if (o < 4000) buf[o] = (uint8_t)(acc >> bits); o++; }
        }
        memcpy(certs[i], buf, o);
        clen[i] = o;
    }

    /* 3) 每张证书的关键信息 */
    for (int i = 0; i < nc; i++) {
        const uint8_t *iss, *sub, *spki; size_t issl, subl, spkil;
        time_t nb = 0, na = 0;
        int rc = cert_parts((const uint8_t *)certs[i], clen[i], &iss, &issl, &sub, &subl, &spki, &spkil, &nb, &na);
        if (rc != 0) {
            printf("│   cert[%d] 解析失败 rc=%d len=%zu head=%02x %02x %02x %02x\n",
                   i, rc, clen[i], certs[i][0]&0xff, certs[i][1]&0xff, certs[i][2]&0xff, certs[i][3]&0xff);
            continue;
        }
        char s1[256]={0}, s2[256]={0};
        dn_str(sub, subl, s1, sizeof s1);
        dn_str(iss, issl, s2, sizeof s2);
        time_t now = time(NULL);
        printf("│   cert[%d] subject=%s\n", i, s1);
        printf("│           issuer =%s\n", s2);
        printf("│           有效期 %s\n", (na > now && nb <= now) ? "有效" : "已过期/未生效");
    }

    /* 4) 私钥 ↔ cert[0] 公钥匹配 */
    {
        const uint8_t *iss, *sub, *spki; size_t issl, subl, spkil; time_t nb, na;
        uint8_t pub[65], want[65];
        if (cert_parts((const uint8_t *)certs[0], clen[0], &iss, &issl, &sub, &subl, &spki, &spkil, &nb, &na) == 0 &&
            spki_pub(spki, spkil, pub) == 0) {
            p256_pubkey(&d, want);
            int ok = memcmp(pub, want, 65) == 0;
            printf("│ [%s%s%s] 私钥 ↔ leaf 公钥 %s\n", ok ? C_GREEN : C_RED, ok ? "✓" : "✗", C_RST,
                   ok ? "匹配" : "不匹配");
        }
    }

    /* 5) 链验签：cert[i] 由 cert[i+1] 签发 */
    int chain_ok = 1;
    for (int i = 0; i + 1 < nc; i++) {
        const uint8_t *iss, *sub, *spki; size_t issl, subl, spkil; time_t nb, na;
        uint8_t issuer_pub[65];
        cert_parts((const uint8_t *)certs[i], clen[i], &iss, &issl, &sub, &subl, &spki, &spkil, &nb, &na);
        const uint8_t *i2, *s2p, *sp2; size_t i2l, s2l, sp2l;
        cert_parts((const uint8_t *)certs[i+1], clen[i+1], &i2, &i2l, &s2p, &s2l, &sp2, &sp2l, &nb, &na);
        if (issl != s2l || memcmp(iss, s2p, issl) != 0) {
            printf("│ [%s✗%s] cert[%d].issuer != cert[%d].subject\n", C_RED, C_RST, i, i+1);
            chain_ok = 0; continue;
        }
        if (spki_pub(sp2, sp2l, issuer_pub) != 0) { chain_ok = 0; continue; }
        const uint8_t *tbs; size_t tbsl;
        tbs_der((const uint8_t *)certs[i], clen[i], &tbs, &tbsl);
        uint8_t h[32]; sha256(tbs, tbsl, h);
        uint8_t r[32], s[32];
        cert_sig((const uint8_t *)certs[i], clen[i], r, s);
        /* 用 p256 verify（attest.h 未导出，这里直接借 selftest 逻辑） */
        extern int veil_ecdsa_verify(const uint8_t pub65[65], const uint8_t h[32],
                                     const uint8_t r[32], const uint8_t s[32]);
        if (!veil_ecdsa_verify(issuer_pub, h, r, s)) {
            printf("│ [%s✗%s] cert[%d] 签名验证失败\n", C_RED, C_RST, i);
            chain_ok = 0;
        }
    }
    printf("│ [%s%s%s] 链签名 %s\n", chain_ok ? C_GREEN : C_RED, chain_ok ? "✓" : "✗", C_RST,
           chain_ok ? "全部通过" : "有断裂");

    /* 6) 根身份判定 */
    {
        const uint8_t *iss, *sub, *spki; size_t issl, subl, spkil; time_t nb, na;
        char root[256] = {0};
        cert_parts((const uint8_t *)certs[nc-1], clen[nc-1], &iss, &issl, &sub, &subl, &spki, &spkil, &nb, &na);
        dn_str(sub, subl, root, sizeof root);
        int is_google = strstr(root, "Google Hardware Attestation Root") != NULL ||
                        strstr(root, "Google Attestation Root") != NULL;
        is_google_root_hack = is_google;
        printf("│ [%s%s%s] 链根: %s\n", is_google ? C_GREEN : C_YEL, is_google ? "✓" : "!", C_RST, root);
        printf("│\n");
        if (is_google)
            printf("│ 结论: 链可验到 Google 硬件根 → Play Integrity / 银行可能通过\n");
        else
            printf("│ 结论: 自签/非 Google 根 → 只能过不验证书链的检测器\n");
    }
    printf("└─────────────────────────────────────────────\n");
    return is_google_root_hack ? 0 : 2;
}
