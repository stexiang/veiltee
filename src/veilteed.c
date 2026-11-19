/* veilteed —— 主守护：注入 keystore2（attestation）+ 目标 App（检测对抗） */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <android/log.h>

#define TAG "VeilTEE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

pid_t veil_find_pid(const char *name);
int   veil_inject(pid_t pid, const char *so_path);

static volatile int g_run = 1;
static void on_sig(int s) { (void)s; g_run = 0; }

/* 读 /proc/<pid>/uid */
static int proc_uid(pid_t pid) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int uid = -1;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "Uid:", 4)) { sscanf(line + 4, "%d", &uid); break; }
    }
    fclose(f);
    return uid;
}

static int proc_cmdline(pid_t pid, char *out, size_t cap) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, cap - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = 0;
    return 0;
}

static int already_injected(pid_t pid) {
    char path[96], buf[256];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int hit = 0;
    while (fgets(buf, sizeof buf, f)) {
        if (strstr(buf, "libveil_app") || strstr(buf, "libveil.so")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

int main(int argc, char **argv) {
    const char *attest_so = "/data/adb/modules/veiltee/bin/libveil.so";
    const char *harden_so = "/data/adb/modules/veiltee/bin/libveil_app.so";
    int watch_all = 0;
    int interval = 3;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--so") && i + 1 < argc) attest_so = argv[++i];
        else if (!strcmp(argv[i], "--harden") && i + 1 < argc) harden_so = argv[++i];
        else if (!strcmp(argv[i], "--watch-all")) watch_all = 1;
        else if (!strcmp(argv[i], "--interval") && i + 1 < argc) interval = atoi(argv[++i]);
    }

    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    pid_t last_ks = 0;
    while (g_run) {
        /* 1) keystore2：attestation 改写 */
        pid_t ks = veil_find_pid("keystore2");
        if (ks && ks != last_ks) {
            if (veil_inject(ks, attest_so) == 0) {
                LOGI("attestation hook -> keystore2 (%d)", ks);
                last_ks = ks;
            }
        } else if (!ks) last_ks = 0;

        /* 2) App 进程：检测对抗 */
        if (watch_all) {
            DIR *d = opendir("/proc");
            if (d) {
                struct dirent *e;
                while ((e = readdir(d))) {
                    if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                    pid_t pid = atoi(e->d_name);
                    if (pid == getpid()) continue;
                    int uid = proc_uid(pid);
                    if (uid < 10000) continue;                  /* 跳过系统进程 */
                    char cmd[256];
                    if (proc_cmdline(pid, cmd, sizeof cmd) != 0) continue;
                    if (cmd[0] == '/') continue;                /* native 服务 */
                    if (already_injected(pid)) continue;
                    if (veil_inject(pid, harden_so) == 0)
                        LOGI("hardening -> %s (%d)", cmd, pid);
                }
                closedir(d);
            }
        }
        sleep((unsigned)interval);
    }
    LOGI("veilteed exiting");
    return 0;
}
