/* hardening.c —— 注入到目标 App 的检测对抗层
 *
 * 核心手法：不 hook 检测函数本身，而是 hook 底层文件系统调用，
 * 用 memfd 提供"净化后的虚拟文件"。检测方无论怎么读，拿到的都是干净内容。
 *
 * 覆盖：root 检测 / hook 框架检测 / 调试检测 / 环境检测 / 完整性检测
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <android/log.h>

#include "veil_cfg.h"

#define TAG "VeilTEE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

extern int veil_plt_hook(const char *sym, void *newfn, void **oldfn);

typedef int (*openat_fn)(int, const char *, int, ...);
typedef int (*open_fn)(const char *, int, ...);
typedef int (*stat_fn)(const char *, struct stat *);
typedef int (*lstat_fn)(const char *, struct stat *);
typedef int (*access_fn)(const char *, int);
typedef ssize_t (*readlink_fn)(const char *, char *, size_t);
typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef long (*ptrace_fn)(long, ...);
typedef char *(*prop_get_fn)(const char *, char *);

static openat_fn   real_openat;
static open_fn     real_open;
static stat_fn     real_stat;
static lstat_fn    real_lstat;
static access_fn   real_access;
static readlink_fn real_readlink;
static execve_fn   real_execve;
static ptrace_fn   real_ptrace;

static veil_cfg g_cfg;

/* ---------------- 拦截规则 ---------------- */

static const char *ROOT_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    "/data/adb/ksu", "/data/adb/magisk", "/sbin/.magisk",
    "/debug_ramdisk", "/data/adb/modules", "/data/adb/veiltee",
    "/system/app/Superuser.apk", "/system/app/SuperSU",
    "/system/etc/init.d/99SuperSUDaemon", "/dev/com.koushikdutta.superuser.daemon",
    "magisk", "Magisk", "supersu", "SuperSU", "busybox",
    "frida", "Frida", "xposed", "Xposed", "lsposed", "LSPosed",
    /* LKM 模式：kernelsu.ko 会出现在 /proc/modules 与 /sys/module/ */
    "kernelsu", "KernelSU", "kernelsu.ko",
    NULL
};

static int is_blocked(const char *path) {
    if (!path) return 0;
    for (int i = 0; ROOT_PATHS[i]; i++)
        if (strstr(path, ROOT_PATHS[i])) return 1;
    return 0;
}

/* 需要净化内容的虚拟文件 */
static int is_sanitize_target(const char *path) {
    if (!path) return 0;
    return !strcmp(path, "/proc/self/status")    ||
           !strcmp(path, "/proc/self/maps")      ||
           !strcmp(path, "/proc/self/smaps")     ||
           !strcmp(path, "/proc/self/mountinfo") ||
           !strcmp(path, "/proc/self/mounts")    ||
           !strcmp(path, "/proc/mounts")         ||
           !strcmp(path, "/proc/net/tcp")        ||
           !strcmp(path, "/proc/net/tcp6")       ||
           !strcmp(path, "/proc/self/cmdline")   ||
           !strcmp(path, "/proc/modules")        ||
           !strcmp(path, "/proc/kallsyms");
}

/* 读原文件并净化 */
static char *sanitize(const char *path, size_t *out_len) {
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) return NULL;

    size_t cap = 1 << 20, n = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    ssize_t r;
    while ((r = read(fd, buf + n, cap - n - 1)) > 0) {
        n += (size_t)r;
        if (n + 2 >= cap) { cap <<= 1; char *nb = realloc(buf, cap); if (!nb) break; buf = nb; }
    }
    close(fd);
    buf[n] = 0;

    char *out = malloc(n + 64);
    if (!out) { free(buf); return NULL; }
    size_t o = 0;

    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) + 1 : strlen(line);

        int drop = 0;
        /* TracerPid 归零 */
        if (!strncmp(line, "TracerPid:", 10)) {
            const char *t = "TracerPid:\t0\n";
            memcpy(out + o, t, strlen(t));
            o += strlen(t);
            drop = 2;
        }
        /* maps / mountinfo 里的敏感映射 */
        if (!drop) {
            for (int i = 0; ROOT_PATHS[i]; i++) {
                if (strstr(line, ROOT_PATHS[i])) { drop = 1; break; }
            }
            if (strstr(line, "libveil") || strstr(line, "memfd:")) drop = 1;
            if (strstr(line, "[anon:veil")) drop = 1;
        }
        if (!drop && (strstr(path, "tcp") || strstr(path, "cmdline"))) {
            /* 屏蔽常见 frida 端口 27042/27043 = 0x69A2/0x69A3 */
            if (strstr(line, "69A2") || strstr(line, "69A3")) drop = 1;
        }
        if (!drop) { memcpy(out + o, line, len); o += len; }

        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    out[o] = 0;
    *out_len = o;
    return out;
}

/* 用 memfd 返回净化后的虚拟文件 */
static int fake_file(const char *path) {
    size_t n = 0;
    char *content = sanitize(path, &n);
    if (!content) return -1;
    int fd = (int)syscall(SYS_memfd_create, "veil", 0);
    if (fd < 0) { free(content); return -1; }
    if (write(fd, content, n) != (ssize_t)n) { close(fd); free(content); return -1; }
    lseek(fd, 0, SEEK_SET);
    free(content);
    return fd;
}

/* ---------------- hook 实现 ---------------- */

static int my_openat(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = (mode_t)va_arg(ap, int);
    va_end(ap);

    if (is_blocked(path)) { errno = ENOENT; return -1; }
    if (is_sanitize_target(path)) {
        int fd = fake_file(path);
        if (fd >= 0) return fd;
    }
    return real_openat(dirfd, path, flags, mode);
}

static int my_open(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = (mode_t)va_arg(ap, int);
    va_end(ap);

    if (is_blocked(path)) { errno = ENOENT; return -1; }
    if (is_sanitize_target(path)) {
        int fd = fake_file(path);
        if (fd >= 0) return fd;
    }
    return real_open(path, flags, mode);
}

static int my_stat(const char *path, struct stat *st) {
    if (is_blocked(path)) { errno = ENOENT; return -1; }
    return real_stat(path, st);
}

static int my_lstat(const char *path, struct stat *st) {
    if (is_blocked(path)) { errno = ENOENT; return -1; }
    return real_lstat(path, st);
}

static int my_access(const char *path, int mode) {
    if (is_blocked(path)) { errno = ENOENT; return -1; }
    return real_access(path, mode);
}

static ssize_t my_readlink(const char *path, char *buf, size_t n) {
    if (is_blocked(path)) { errno = ENOENT; return -1; }
    return real_readlink(path, buf, n);
}

/* su / magisk 执行一律 ENOENT */
static int my_execve(const char *path, char *const argv[], char *const envp[]) {
    if (is_blocked(path)) { errno = ENOENT; return -1; }
    return real_execve(path, argv, envp);
}

/* PTRACE_TRACEME 假装成功但不真正 trace */
static long my_ptrace(long req, ...) {
    va_list ap; va_start(ap, req);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (req == PTRACE_TRACEME) return 0;
    return real_ptrace(req, pid, addr, data);
}

/* 属性层：屏蔽 magisk/ksu 相关属性读取 */
typedef int (*prop_get2_fn)(const char *, char *, uint32_t);
static prop_get2_fn real_prop_get2;

static int my_prop_get2(const char *key, char *val, uint32_t len) {
    if (key && (strstr(key, "magisk") || strstr(key, "ksu") ||
                strstr(key, "veil"))) {
        if (val && len) val[0] = 0;
        return 0;
    }
    return real_prop_get2 ? real_prop_get2(key, val, len) : 0;
}

__attribute__((constructor))
static void veil_harden_init(void) {
    veil_cfg_load(&g_cfg, "/data/adb/veiltee/veil.conf");
    if (!g_cfg.enabled) return;

    void *p;
    veil_plt_hook("openat",    (void *)my_openat,   (void **)&real_openat);
    veil_plt_hook("open",      (void *)my_open,     (void **)&real_open);
    veil_plt_hook("stat",      (void *)my_stat,     (void **)&real_stat);
    veil_plt_hook("lstat",     (void *)my_lstat,    (void **)&real_lstat);
    veil_plt_hook("access",    (void *)my_access,   (void **)&real_access);
    veil_plt_hook("readlink",  (void *)my_readlink, (void **)&real_readlink);
    veil_plt_hook("execve",    (void *)my_execve,   (void **)&real_execve);
    veil_plt_hook("ptrace",    (void *)my_ptrace,   (void **)&real_ptrace);

    if (!real_prop_get2) {
        p = dlsym(RTLD_DEFAULT, "__system_property_get");
        if (p) veil_plt_hook("__system_property_get", (void *)my_prop_get2, (void **)&real_prop_get2);
    }
    LOGI("hardening installed");
}
