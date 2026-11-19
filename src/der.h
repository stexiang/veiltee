/* der.h —— 零依赖 DER/TLV 编码工具（VeilTEE） */
#ifndef VEIL_DER_H
#define VEIL_DER_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DER_MAX 4096

static inline size_t der_len(uint8_t *o, size_t n) {
    if (n < 0x80)      { o[0] = (uint8_t)n; return 1; }
    if (n < 0x100)     { o[0] = 0x81; o[1] = (uint8_t)n; return 2; }
    if (n < 0x10000)   { o[0] = 0x82; o[1] = (uint8_t)(n >> 8); o[2] = (uint8_t)n; return 3; }
    o[0] = 0x83; o[1] = (uint8_t)(n >> 16); o[2] = (uint8_t)(n >> 8); o[3] = (uint8_t)n;
    return 4;
}

/* 追加 TLV 到 buf[*pos..]，返回新 pos */
static inline size_t der_put(uint8_t *buf, size_t pos, uint8_t tag,
                             const uint8_t *val, size_t n) {
    buf[pos++] = tag;
    pos += der_len(buf + pos, n);
    if (n && val) memcpy(buf + pos, val, n);
    return pos + n;
}

/* 原地把 buf[start..pos] 的内容包一层 TLV（预留 header 区由调用方处理） */
static inline size_t der_wrap(uint8_t *buf, size_t pos, uint8_t tag) {
    uint8_t hdr[8];
    size_t hl = 1 + der_len(hdr + 1, pos);
    hdr[0] = tag;
    memmove(buf + hl, buf, pos);
    memcpy(buf, hdr, hl);
    return pos + hl;
}

/* 整数：最小大端补码编码 */
static inline size_t der_int(uint8_t *buf, size_t pos, const uint8_t *be, size_t n) {
    while (n > 1 && be[0] == 0x00 && !(be[1] & 0x80)) { be++; n--; }
    int need_pad = (n > 0 && (be[0] & 0x80));
    uint8_t tmp[40];
    size_t tn = 0;
    if (need_pad) tmp[tn++] = 0x00;
    if (n == 0) { tmp[tn++] = 0x00; }
    else { memcpy(tmp + tn, be, n); tn += n; }
    return der_put(buf, pos, 0x02, tmp, tn);
}

static inline size_t der_uint64(uint8_t *buf, size_t pos, uint64_t v) {
    uint8_t b[8]; size_t n = 0;
    do { b[7 - n] = (uint8_t)(v & 0xFF); v >>= 8; n++; } while (v);
    return der_int(buf, pos, b + 8 - n, n);
}

static inline size_t der_oid(uint8_t *buf, size_t pos, const uint8_t *oid, size_t n) {
    return der_put(buf, pos, 0x06, oid, n);
}

static inline size_t der_octets(uint8_t *buf, size_t pos, const uint8_t *v, size_t n) {
    return der_put(buf, pos, 0x04, v, n);
}

static inline size_t der_bitstring(uint8_t *buf, size_t pos, const uint8_t *v, size_t n) {
    buf[pos++] = 0x03;
    pos += der_len(buf + pos, n + 1);
    buf[pos++] = 0x00;              /* unused bits */
    if (n) memcpy(buf + pos, v, n);
    return pos + n;
}

static inline size_t der_bool(uint8_t *buf, size_t pos, int v) {
    uint8_t b = v ? 0xFF : 0x00;
    return der_put(buf, pos, 0x01, &b, 1);
}

static inline size_t der_seq_begin(uint8_t *buf, size_t pos) {
    buf[pos++] = 0x30;
    pos += der_len(buf + pos, 0);
    return pos;                     /* 返回内容起点，收尾用 der_seq_end */
}

/* 重新计算 buf[start-?..pos] 的 SEQUENCE 长度 */
static inline size_t der_seq_fix(uint8_t *buf, size_t start, size_t pos) {
    size_t content = pos - start;
    uint8_t hdr[8];
    size_t hl = 1 + der_len(hdr + 1, content);
    hdr[0] = 0x30;
    memmove(buf + start + hl, buf + start, content);
    memcpy(buf + start, hdr, hl);
    return start + hl + content;
}

/* context-specific constructed，high-tag-number（tag > 30） */
static inline size_t der_ctx(uint8_t *buf, size_t pos, uint32_t tag,
                             const uint8_t *val, size_t n) {
    uint8_t t[6]; size_t tn = 0;
    t[tn++] = 0xBF;                 /* context | constructed | 0x1F */
    uint8_t tmp[5]; int i = 0;
    uint32_t v = tag;
    do { tmp[i++] = (uint8_t)(v & 0x7F); v >>= 7; } while (v);
    for (int k = i - 1; k >= 0; k--) t[tn++] = tmp[k] | (k ? 0x80 : 0x00);

    buf[pos++] = t[0];
    for (size_t k = 1; k < tn; k++) buf[pos++] = t[k];
    pos += der_len(buf + pos, n);
    if (n && val) memcpy(buf + pos, val, n);
    return pos + n;
}

/* 通用：包一层 context tag（同 der_ctx，供外部拼好的内容使用） */
static inline size_t der_ctx_wrap(uint8_t *buf, size_t pos, uint32_t tag) {
    uint8_t t[6]; size_t tn = 0, hl;
    t[tn++] = 0xBF;
    uint8_t tmp[5]; int i = 0;
    uint32_t v = tag;
    do { tmp[i++] = (uint8_t)(v & 0x7F); v >>= 7; } while (v);
    for (int k = i - 1; k >= 0; k--) t[tn++] = tmp[k] | (k ? 0x80 : 0x00);

    uint8_t lenb[8];
    size_t ll = der_len(lenb, pos);
    hl = tn + ll;
    memmove(buf + hl, buf, pos);
    memcpy(buf, t, tn);
    memcpy(buf + tn, lenb, ll);
    return pos + hl;
}


/* context-specific constructed，low tag（0..30），用于 [0]/[3] 这类 */
static inline size_t der_ctx_low(uint8_t *buf, size_t pos, uint8_t tag,
                                 const uint8_t *val, size_t n) {
    return der_put(buf, pos, (uint8_t)(0xA0 | tag), val, n);
}

#endif
