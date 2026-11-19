/* veil_cfg.c —— 极简 key=value 配置 + keybox.xml 提取 */
#include "veil_cfg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int veil_hex2bin(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex);
    if (n != cap * 2) return -1;
    for (size_t i = 0; i < cap; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* 从 XML 里提取 PEM 块 */
static int extract_pem_block(const char *xml, const char *tag, char *out, size_t cap) {
    char beg[64], end[64];
    snprintf(beg, sizeof beg, "-----BEGIN %s-----", tag);
    snprintf(end, sizeof end, "-----END %s-----", tag);
    const char *b = strstr(xml, beg);
    if (!b) return -1;
    const char *e = strstr(b, end);
    if (!e) return -1;
    e += strlen(end);
    size_t n = (size_t)(e - b);
    if (n >= cap) return -1;
    memcpy(out, b, n);
    out[n] = 0;
    return 0;
}

static int extract_keybox(const char *xml, char *priv, char *cert) {
    if (extract_pem_block(xml, "EC PRIVATE KEY", priv, VEIL_PEM_MAX) != 0 &&
        extract_pem_block(xml, "PRIVATE KEY", priv, VEIL_PEM_MAX) != 0)
        return -1;
    if (extract_pem_block(xml, "CERTIFICATE", cert, VEIL_PEM_MAX) != 0)
        return -1;
    return 0;
}

int veil_cfg_load(veil_cfg *c, const char *conf_path) {
    memset(c, 0, sizeof *c);
    c->enabled = 1;
    c->device_locked = 1;
    c->boot_state = 0;
    c->security_level = 1;
    c->os_version = 16;
    strcpy(c->patch_level, "2026-11-05");
    strcpy(c->state_dir, "/data/adb/veiltee");

    FILE *f = fopen(conf_path, "r");
    if (!f) return -1;

    char keybox_path[512] = "/data/adb/modules/veiltee/config/keybox.xml";
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *e = v + strlen(v);
        while (e > v && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = 0;

        if (!strcmp(k, "enabled")) c->enabled = atoi(v);
        else if (!strcmp(k, "device_locked")) c->device_locked = atoi(v);
        else if (!strcmp(k, "boot_state")) c->boot_state = atoi(v);
        else if (!strcmp(k, "security_level")) c->security_level = atoi(v);
        else if (!strcmp(k, "os_version")) c->os_version = atoi(v);
        else if (!strcmp(k, "patch_level")) snprintf(c->patch_level, sizeof c->patch_level, "%s", v);
        else if (!strcmp(k, "vb_key")) snprintf(c->vb_key_hex, sizeof c->vb_key_hex, "%s", v);
        else if (!strcmp(k, "vb_hash")) snprintf(c->vb_hash_hex, sizeof c->vb_hash_hex, "%s", v);
        else if (!strcmp(k, "state_dir")) snprintf(c->state_dir, sizeof c->state_dir, "%s", v);
        else if (!strcmp(k, "keybox")) snprintf(keybox_path, sizeof keybox_path, "%s", v);
    }
    fclose(f);

    /* vb_key / vb_hash 回退：从 state_dir 读 post-fs-data.sh 落盘的 digest */
    if (!c->vb_key_hex[0]) {
        char path[512]; snprintf(path, sizeof path, "%s/vb_key", c->state_dir);
        FILE *vf = fopen(path, "r");
        if (vf) { if (fscanf(vf, "%64s", c->vb_key_hex) != 1) c->vb_key_hex[0] = 0; fclose(vf); }
    }
    if (!c->vb_hash_hex[0]) {
        char path[512]; snprintf(path, sizeof path, "%s/vb_hash", c->state_dir);
        FILE *vf = fopen(path, "r");
        if (vf) { if (fscanf(vf, "%64s", c->vb_hash_hex) != 1) c->vb_hash_hex[0] = 0; fclose(vf); }
    }

    /* keybox.xml */
    FILE *kb = fopen(keybox_path, "r");
    if (kb) {
        static char xml[65536];
        size_t n = fread(xml, 1, sizeof xml - 1, kb);
        xml[n] = 0;
        fclose(kb);
        if (extract_keybox(xml, c->keybox_priv, c->keybox_cert) != 0) {
            c->keybox_priv[0] = c->keybox_cert[0] = 0;
        }
    }
    return 0;
}
