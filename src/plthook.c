/* plthook.c —— 只改 GOT，不动代码段（maps 无新增可执行映射） */
#define _GNU_SOURCE
#include <link.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/cdefs.h>

#if defined(__aarch64__)
#  define VEIL_JUMP_SLOT R_AARCH64_JUMP_SLOT
#  define ELF_RELA Elf64_Rela
#  define R_SYM(i) ELF64_R_SYM(i)
#  define R_TYPE(i) ELF64_R_TYPE(i)
#elif defined(__x86_64__)
#  define VEIL_JUMP_SLOT R_X86_64_JUMP_SLOT
#  define ELF_RELA Elf64_Rela
#  define R_SYM(i) ELF64_R_SYM(i)
#  define R_TYPE(i) ELF64_R_TYPE(i)
#endif

struct patch_req {
    const char *name;
    void       *newfn;
    void      **oldfn;
    int         done;
};

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    struct patch_req *req = data;
    if (req->done) return 1;

    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    const Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    const ELF_RELA *jmprel = NULL;
    size_t pltrelsz = 0;

    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:  symtab  = (const void *)(info->dlpi_addr + d->d_un.d_ptr); break;
            case DT_STRTAB:  strtab  = (const void *)(info->dlpi_addr + d->d_un.d_ptr); break;
            case DT_JMPREL:  jmprel  = (const void *)(info->dlpi_addr + d->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
            default: break;
        }
    }
    if (!symtab || !strtab || !jmprel || !pltrelsz) return 0;

    size_t n = pltrelsz / sizeof(ELF_RELA);
    for (size_t i = 0; i < n; i++) {
        if (R_TYPE(jmprel[i].r_info) != VEIL_JUMP_SLOT) continue;
        unsigned si = (unsigned)R_SYM(jmprel[i].r_info);
        const char *sname = strtab + symtab[si].st_name;
        if (!sname || strcmp(sname, req->name) != 0) continue;

        void **got = (void **)(info->dlpi_addr + jmprel[i].r_offset);
        long pg = sysconf(_SC_PAGESIZE);
        uintptr_t page = (uintptr_t)got & ~(uintptr_t)(pg - 1);
        if (mprotect((void *)page, (size_t)pg * 2,
                     PROT_READ | PROT_WRITE) != 0) continue;

        if (req->oldfn && !*req->oldfn) *req->oldfn = *got;
        *got = req->newfn;

        mprotect((void *)page, (size_t)pg * 2, PROT_READ);
        req->done = 1;
        return 1;
    }
    return 0;      /* 继续下一个 so */
}

/* 返回 0 成功 */
int veil_plt_hook(const char *sym, void *newfn, void **oldfn) {
    struct patch_req req = { sym, newfn, oldfn, 0 };
    dl_iterate_phdr(phdr_cb, &req);
    return req.done ? 0 : -1;
}
