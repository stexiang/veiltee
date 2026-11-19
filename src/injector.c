/* injector.c —— ptrace 注入（不需要 Zygisk / LSPosed） */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <android/log.h>

#define TAG "VeilTEE"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static pid_t g_pid;

static unsigned long lib_base(pid_t pid, const char *name) {
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long base = 0;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, name) && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-", &base) == 1) break;
        }
    }
    fclose(f);
    return base;
}

static unsigned long remote_addr(unsigned long local_addr, const char *soname) {
    unsigned long lb = lib_base(getpid(), soname);
    unsigned long tb = lib_base(g_pid, soname);
    if (!lb || !tb) return 0;
    return local_addr - lb + tb;
}

/* 在目标进程里执行一次函数调用（arm64） */
static unsigned long remote_call(unsigned long fn, unsigned long a0, unsigned long a1,
                                 unsigned long a2, unsigned long a3,
                                 unsigned long a4, unsigned long a5) {
#if defined(__aarch64__)
    struct user_pt_regs regs, saved;
    if (ptrace(PTRACE_GETREGSET, g_pid, (void *)1, &saved) != 0) return 0;
    regs = saved;
    regs.regs[0] = a0; regs.regs[1] = a1; regs.regs[2] = a2;
    regs.regs[3] = a3; regs.regs[4] = a4; regs.regs[5] = a5;
    regs.pc = fn;
    regs.regs[30] = 0;            /* lr = 0 → 返回即崩溃点，用 SIGSEGV 捕获 */
    if (ptrace(PTRACE_SETREGSET, g_pid, (void *)1, &regs) != 0) return 0;
    ptrace(PTRACE_CONT, g_pid, NULL, NULL);
    int st;
    waitpid(g_pid, &st, 0);
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
        /* 正常返回：lr=0 触发 SIGSEGV */
        if (ptrace(PTRACE_GETREGSET, g_pid, (void *)1, &regs) != 0) return 0;
        unsigned long ret = regs.regs[0];
        ptrace(PTRACE_SETREGSET, g_pid, (void *)1, &saved);
        return ret;
    }
    ptrace(PTRACE_SETREGSET, g_pid, (void *)1, &saved);
    return 0;
#else
    (void)fn; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    return 0;
#endif
}

static int write_remote(unsigned long addr, const void *buf, size_t len) {
    struct iovec local = { (void *)buf, len };
    struct iovec remote = { (void *)addr, len };
    return process_vm_writev(g_pid, &local, 1, &remote, 1, 0) == (ssize_t)len ? 0 : -1;
}

int veil_inject(pid_t pid, const char *so_path) {
    g_pid = pid;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        LOGI("attach failed: %s", strerror(errno));
        return -1;
    }
    int st;
    waitpid(pid, &st, 0);

    unsigned long mmap_fn  = remote_addr((unsigned long)mmap, "libc.so");
    unsigned long dlopen_fn = remote_addr((unsigned long)dlopen, "libc.so");
    if (!mmap_fn || !dlopen_fn) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return -2; }

    /* mmap(NULL, 4096, RWX, MAP_PRIVATE|MAP_ANON, -1, 0) */
    unsigned long mem = remote_call(mmap_fn, 0, 4096,
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                    (unsigned long)-1, 0);
    if (!mem) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return -3; }

    if (write_remote(mem, so_path, strlen(so_path) + 1) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -4;
    }

    unsigned long h = remote_call(dlopen_fn, mem, 2 /* RTLD_NOW */, 0, 0, 0, 0);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    LOGI("inject %s -> handle=%lx", so_path, h);
    return h ? 0 : -5;
}

pid_t veil_find_pid(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    pid_t found = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[64], buf[256] = {0};
        snprintf(path, sizeof path, "/proc/%s/cmdline", e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        read(fd, buf, sizeof buf - 1);
        close(fd);
        if (strcmp(buf, name) == 0) { found = atoi(e->d_name); break; }
    }
    closedir(d);
    return found;
}
