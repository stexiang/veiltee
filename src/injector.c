/* injector.c —— ptrace 注入（不依赖 Zygisk / LSPosed / susfs）
 *
 * 关键：--memfd 模式下 so 内容全程在内存，
 *       目标进程 maps 里只显示 /memfd:veil (deleted)，磁盘上不留可加载路径。
 */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/syscall.h>
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

/* 在目标进程里执行一次调用（arm64）。lr=0 → SIGSEGV 即返回 */
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
    regs.regs[30] = 0;
    if (ptrace(PTRACE_SETREGSET, g_pid, (void *)1, &regs) != 0) return 0;
    ptrace(PTRACE_CONT, g_pid, NULL, NULL);
    int st;
    waitpid(g_pid, &st, 0);
    unsigned long ret = 0;
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
        if (ptrace(PTRACE_GETREGSET, g_pid, (void *)1, &regs) == 0) ret = regs.regs[0];
    }
    ptrace(PTRACE_SETREGSET, g_pid, (void *)1, &saved);
    return ret;
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

/* 把磁盘上的 so 读进目标进程的 memfd，返回 fd（失败 -1） */
static long load_to_memfd(const char *so_path, unsigned long scratch,
                          unsigned long mmap_fn, unsigned long syscall_fn,
                          unsigned long write_fn, unsigned long *path_addr) {
    int f = open(so_path, O_RDONLY);
    if (f < 0) return -1;
    struct stat st;
    if (fstat(f, &st) != 0 || st.st_size <= 0) { close(f); return -1; }
    size_t size = (size_t)st.st_size;
    uint8_t *buf = malloc(size);
    if (!buf) { close(f); return -1; }
    size_t got = 0;
    ssize_t n;
    while ((n = read(f, buf + got, size - got)) > 0) got += (size_t)n;
    close(f);
    if (got != size) { free(buf); return -1; }

    /* 目标进程里 mmap 一块容纳 so + 路径的空间 */
    size_t need = size + 512;
    unsigned long mem = remote_call(mmap_fn, 0, need,
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                    (unsigned long)-1, 0);
    if (!mem) { free(buf); return -1; }

    /* memfd_create("veil", 0) */
    char name[8] = "veil";
    write_remote(mem, name, sizeof name);
    long mfd = (long)remote_call(syscall_fn, SYS_memfd_create, mem, 0, 0, 0, 0);
    if (mfd < 0) { free(buf); return -1; }

    /* 把 so 拷进目标内存，再 write 到 memfd */
    if (write_remote(mem, buf, size) != 0) { free(buf); return -1; }
    free(buf);
    long wr = (long)remote_call(write_fn, (unsigned long)mfd, mem, size, 0, 0, 0);
    if (wr != (long)size) return -1;

    /* 拼 /proc/self/fd/<mfd> 到同一块内存 */
    char path[64];
    int pl = snprintf(path, sizeof path, "/proc/self/fd/%ld", mfd);
    if (write_remote(mem, path, (size_t)pl + 1) != 0) return -1;
    *path_addr = mem;
    return mfd;
}

int veil_inject_ex(pid_t pid, const char *so_path, int use_memfd) {
    g_pid = pid;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;
    int st;
    waitpid(pid, &st, 0);

    unsigned long mmap_fn    = remote_addr((unsigned long)mmap, "libc.so");
    unsigned long dlopen_fn  = remote_addr((unsigned long)dlopen, "libc.so");
    unsigned long syscall_fn = remote_addr((unsigned long)syscall, "libc.so");
    unsigned long write_fn   = remote_addr((unsigned long)write, "libc.so");
    if (!mmap_fn || !dlopen_fn) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return -2; }

    unsigned long mem = 0;
    int ok = -1;

    if (use_memfd && syscall_fn && write_fn) {
        unsigned long path_addr = 0;
        long mfd = load_to_memfd(so_path, 0, mmap_fn, syscall_fn, write_fn, &path_addr);
        if (mfd >= 0) {
            unsigned long h = remote_call(dlopen_fn, path_addr, 2, 0, 0, 0, 0);
            LOGI("memfd inject %s (fd=%ld) -> handle=%lx", so_path, mfd, h);
            if (h) ok = 0;
        }
    }

    if (ok != 0) {
        /* 回退：直接 dlopen 磁盘路径 */
        mem = remote_call(mmap_fn, 0, 4096,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          (unsigned long)-1, 0);
        if (mem && write_remote(mem, so_path, strlen(so_path) + 1) == 0) {
            unsigned long h = remote_call(dlopen_fn, mem, 2, 0, 0, 0, 0);
            LOGI("disk inject %s -> handle=%lx", so_path, h);
            if (h) ok = 0;
        }
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ok;
}

int veil_inject(pid_t pid, const char *so_path) {
    return veil_inject_ex(pid, so_path, 0);
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
