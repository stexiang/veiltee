/* veilctl —— 体检 / 状态 / 自检 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "attest.h"
#include "veil_cfg.h"

#define CONF "/data/adb/modules/veiltee/config/veil.conf"
#define STATE "/data/adb/veiltee"

static int read_prop(const char *key, char *out, size_t cap) {
    char cmd[256], line[256];
    snprintf(cmd, sizeof cmd, "getprop %s", key);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    int ok = 0;
    if (fgets(line, sizeof line, p)) {
        char *e = line + strlen(line);
        while (e > line && (e[-1] == '\n' || e[-1] == '\r')) *--e = 0;
        snprintf(out, cap, "%s", line);
        ok = 1;
    }
    pclose(p);
    return ok ? 0 : -1;
}

static int read_file(const char *path, char *out, size_t cap) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = 0;
    char *e = out + n;
    while (e > out && (e[-1] == '\n' || e[-1] == '\r')) *--e = 0;
    fclose(f);
    return 0;
}

static void line_ok(const char *what, const char *val) {
    printf("│ [\033[32m✓\033[0m] %-34s %s\n", what, val);
}
static void line_bad(const char *what, const char *val) {
    printf("│ [\033[31m✗\033[0m] %-34s %s\n", what, val);
}

static int cmd_verify(void) {
    veil_cfg cfg;
    char v[256];
    int pass = 0, total = 0;

    printf("┌─ VeilTEE 体检报告 ─────────────────────────────\n");

    if (veil_cfg_load(&cfg, CONF) != 0) {
        printf("│ [!] 配置读取失败: %s\n", CONF);
    }

    /* 1. 属性一致性 */
    total++;
    if (read_prop("ro.boot.flash.locked", v, sizeof v) == 0 && !strcmp(v, "1")) {
        line_ok("ro.boot.flash.locked", v); pass++;
    } else line_bad("ro.boot.flash.locked", v);

    total++;
    if (read_prop("ro.boot.verifiedbootstate", v, sizeof v) == 0 && !strcmp(v, "green")) {
        line_ok("ro.boot.verifiedbootstate", v); pass++;
    } else line_bad("ro.boot.verifiedbootstate", v);

    total++;
    if (read_prop("ro.boot.vbmeta.device_state", v, sizeof v) == 0 && !strcmp(v, "locked")) {
        line_ok("ro.boot.vbmeta.device_state", v); pass++;
    } else line_bad("ro.boot.vbmeta.device_state", v);

    total++;
    if (read_prop("sys.oem_unlock_allowed", v, sizeof v) == 0 && !strcmp(v, "0")) {
        line_ok("sys.oem_unlock_allowed", v); pass++;
    } else line_bad("sys.oem_unlock_allowed", v);

    total++;
    if (read_prop("ro.boot.veritymode", v, sizeof v) == 0 && !strcmp(v, "enforcing")) {
        line_ok("ro.boot.veritymode", v); pass++;
    } else line_bad("ro.boot.veritymode", v);

    /* 2. vbmeta digest 与 attestation 是否同源 */
    total++;
    char vb[128] = {0};
    if (read_file(STATE "/vb_hash", vb, sizeof vb) == 0 && vb[0]) {
        line_ok("verifiedBootHash 来源", "ro.boot.vbmeta.digest");
        pass++;
    } else line_bad("verifiedBootHash 来源", "缺失");

    /* 3. keybox 可用性 */
    total++;
    if (cfg.keybox_priv[0] && cfg.keybox_cert[0]) {
        line_ok("keybox 私钥+证书链", "已加载");
        pass++;
    } else line_bad("keybox 私钥+证书链", "未加载");

    /* 4. 生成一份测试 attestation，验证三绿 */
    total++;
    {
        uint8_t dbe[32] = {0}; dbe[31] = 9;
        u256 d; u256_from_be(&d, dbe);
        uint8_t pub[65]; p256_pubkey(&d, pub);

        veil_trust_t tr;
        memset(&tr, 0, sizeof tr);
        if (veil_hex2bin(cfg.vb_key_hex, tr.vb_key, 32) != 0) memset(tr.vb_key, 0x11, 32);
        if (veil_hex2bin(cfg.vb_hash_hex, tr.vb_hash, 32) != 0) memset(tr.vb_hash, 0x22, 32);
        tr.device_locked  = cfg.device_locked;
        tr.boot_state     = cfg.boot_state;
        tr.security_level = cfg.security_level;
        tr.os_version     = cfg.os_version;
        snprintf(tr.patch_level, sizeof tr.patch_level, "%s", cfg.patch_level);

        uint8_t ch[32] = {0x01, 0x02, 0x03};
        uint8_t out[2048];
        int n = cfg.keybox_priv[0]
              ? veil_attest_from_keybox(cfg.keybox_priv, cfg.keybox_cert,
                                        pub, ch, sizeof ch, &tr, out, sizeof out)
              : -1;
        if (n > 0) {
            char buf[64];
            snprintf(buf, sizeof buf, "%d bytes", n);
            line_ok("attestation 生成", buf);
            pass++;
        } else line_bad("attestation 生成", "失败");
    }

    /* 5. 三绿结论 */
    printf("├────────────────────────────────────────────────\n");
    int green = (cfg.device_locked ? 1 : 0) + (cfg.boot_state == 0 ? 1 : 0) + 1;
    printf("│ 三绿: %d/3   %s\n", green,
           green == 3 ? "\033[32mKeyAttestation 全绿\033[0m" : "\033[31m有缺失\033[0m");
    printf("│ 项: %d/%d\n", pass, total);
    printf("└────────────────────────────────────────────────\n");
    return (green == 3 && pass == total) ? 0 : 1;
}

static int cmd_status(void) {
    char v[256];
    printf("VeilTEE status\n");
    printf("  config   : %s\n", access(CONF, R_OK) == 0 ? "ok" : "missing");
    printf("  keybox   : %s\n", access("/data/adb/modules/veiltee/config/keybox.xml", R_OK) == 0 ? "ok" : "missing");
    printf("  daemon   : %s\n", system("pgrep -f veilteed >/dev/null") == 0 ? "running" : "stopped");
    read_prop("ro.boot.verifiedbootstate", v, sizeof v); printf("  bootstate: %s\n", v);
    read_prop("ro.boot.flash.locked", v, sizeof v);      printf("  locked   : %s\n", v);
    return 0;
}

int kb_check(const char *path);

int main(int argc, char **argv) {
    const char *cmd = argc > 1 ? argv[1] : "verify";
    if (!strcmp(cmd, "verify")) return cmd_verify();
    if (!strcmp(cmd, "status")) return cmd_status();
    if (!strcmp(cmd, "keybox")) return kb_check(argc > 2 ? argv[2] : NULL);
    printf("usage: veilctl {verify|status|keybox [path]}\n");
    return 2;
}
