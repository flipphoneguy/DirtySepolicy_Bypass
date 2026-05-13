// DirtySepolicy Bypass — Zygisk module
//
// Defeats DirtySepolicy v2.0 detection by:
// 1. PLT-hooking selinux_check_access / security_compute_av(_flags) to hide
//    probes whose scon/tcon contains a known framework type name.
// 2. PLT-hooking open/write/close to intercept contextExists() checks that
//    write directly to /sys/fs/selinux/context and /proc/self/attr/current.
// 3. Blocking exact (scon,tcon,class,perm) tuples for indirect probes that
//    use only stock context names but reveal framework-injected allow rules.

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android/log.h>
#include "zygisk.hpp"

#define LOG_TAG "DirtySepBypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

void *operator new   (size_t s)              { return malloc(s); }
void *operator new[] (size_t s)              { return malloc(s); }
void  operator delete   (void *p) noexcept   { free(p); }
void  operator delete[] (void *p) noexcept   { free(p); }
void  operator delete   (void *p, size_t) noexcept { free(p); }
void  operator delete[] (void *p, size_t) noexcept { free(p); }

// ---- libselinux ABI (mirrored locally) ----------------------------------

typedef unsigned int   access_vector_t;
typedef unsigned short security_class_t;

struct av_decision {
    access_vector_t allowed;
    access_vector_t decided;
    access_vector_t auditallow;
    access_vector_t auditdeny;
    unsigned int    seqno;
    unsigned int    flags;
};

// ---- hidden context substrings ------------------------------------------

static const char *const kHidden[] = {
    ":magisk",     ":kitsune",    ":apatch",
    ":ksu",        ":kernelsu",
    ":lsposed",    ":xposed",     ":riru",
    ":adbroot",
    ":supersu",    ":supolicy",   ":su:",
    ":zygisk",
    nullptr,
};

static inline bool is_hidden(const char *con) {
    if (!con) return false;
    for (int i = 0; kHidden[i]; ++i) {
        if (strstr(con, kHidden[i])) return true;
    }
    return false;
}

// ---- hidden permissions (hygiene probes) ---------------------------------

static const char *const kHiddenPerms[] = {
    "execmem",
    nullptr,
};

static inline bool is_hidden_perm(const char *perm) {
    if (!perm) return false;
    for (int i = 0; kHiddenPerms[i]; ++i) {
        if (strcmp(perm, kHiddenPerms[i]) == 0) return true;
    }
    return false;
}

// ---- exact-match probes (stock contexts, framework-injected rules) ------

struct ExactProbe {
    const char *scon;
    const char *tcon;
    const char *tclass;
    const char *perm;
};

static const ExactProbe kHiddenExact[] = {
    // Magisk: tmpfs mounts on rootfs, kernel fifo access to tmpfs
    {"u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"},
    {"u:r:kernel:s0",        "u:object_r:tmpfs:s0", "fifo_file",  "open"},
    // KernelSU: kernel reads adb_data_file
    {"u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"},
    // LSPosed: system_server executes injected APKs
    {"u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"},
    // Xposed: dex2oat execute_no_trans
    {"u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"},
    // ZygiskNext: zygote searches adb_data_file dirs
    {"u:r:zygote:s0",        "u:object_r:adb_data_file:s0", "dir",  "search"},
    {nullptr, nullptr, nullptr, nullptr},
};

static inline bool is_hidden_exact(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm) {
    if (!scon || !tcon || !tclass || !perm) return false;
    for (int i = 0; kHiddenExact[i].scon; ++i) {
        if (strcmp(scon, kHiddenExact[i].scon) == 0 &&
            strcmp(tcon, kHiddenExact[i].tcon) == 0 &&
            strcmp(tclass, kHiddenExact[i].tclass) == 0 &&
            strcmp(perm, kHiddenExact[i].perm) == 0) {
            return true;
        }
    }
    return false;
}

// ---- numeric resolution for security_compute_av -------------------------

struct ClassPerm { const char *cls; const char *perm; };
static const ClassPerm kHiddenClassPerms[] = {
    { "process", "execmem" },
    { nullptr, nullptr },
};

struct ResolvedBit {
    security_class_t cls_id;
    access_vector_t  perm_bit;
};
static ResolvedBit g_hidden_bits[8] = {};
static int         g_hidden_bit_count = 0;

struct ExactBit {
    const char      *scon;
    const char      *tcon;
    security_class_t cls_id;
    access_vector_t  perm_bit;
};
static ExactBit g_exact_bits[16] = {};
static int      g_exact_bit_count = 0;

static bool g_bits_resolved = false;

static void resolve_hidden_bits() {
    if (g_bits_resolved) return;
    auto str_to_cls  = (security_class_t (*)(const char *))
        dlsym(RTLD_DEFAULT, "string_to_security_class");
    auto str_to_perm = (access_vector_t (*)(security_class_t, const char *))
        dlsym(RTLD_DEFAULT, "string_to_av_perm");
    if (str_to_cls && str_to_perm) {
        for (int i = 0;
             kHiddenClassPerms[i].cls && g_hidden_bit_count < 8;
             ++i) {
            security_class_t cid = str_to_cls(kHiddenClassPerms[i].cls);
            if (!cid) continue;
            access_vector_t pbit = str_to_perm(cid, kHiddenClassPerms[i].perm);
            if (!pbit) continue;
            g_hidden_bits[g_hidden_bit_count++] = { cid, pbit };
        }
        for (int i = 0;
             kHiddenExact[i].scon && g_exact_bit_count < 16;
             ++i) {
            security_class_t cid = str_to_cls(kHiddenExact[i].tclass);
            if (!cid) continue;
            access_vector_t pbit = str_to_perm(cid, kHiddenExact[i].perm);
            if (!pbit) continue;
            g_exact_bits[g_exact_bit_count++] = {
                kHiddenExact[i].scon, kHiddenExact[i].tcon, cid, pbit
            };
        }
    }
    g_bits_resolved = true;
}

static inline void mask_hidden_bits(security_class_t tclass, av_decision *avd) {
    if (!avd) return;
    for (int i = 0; i < g_hidden_bit_count; ++i) {
        if (g_hidden_bits[i].cls_id == tclass) {
            avd->allowed    &= ~g_hidden_bits[i].perm_bit;
            avd->auditallow &= ~g_hidden_bits[i].perm_bit;
        }
    }
}

static inline void mask_exact_bits(const char *scon, const char *tcon,
                                   security_class_t tclass, av_decision *avd) {
    if (!avd || !scon || !tcon) return;
    for (int i = 0; i < g_exact_bit_count; ++i) {
        if (g_exact_bits[i].cls_id == tclass &&
            strcmp(scon, g_exact_bits[i].scon) == 0 &&
            strcmp(tcon, g_exact_bits[i].tcon) == 0) {
            avd->allowed    &= ~g_exact_bits[i].perm_bit;
            avd->auditallow &= ~g_exact_bits[i].perm_bit;
        }
    }
}

static void fake_deny(av_decision *avd) {
    if (!avd) return;
    avd->allowed    = 0;
    avd->decided    = ~0u;
    avd->auditallow = 0;
    avd->auditdeny  = ~0u;
    avd->seqno      = 0;
    avd->flags      = 0;
}

// ---- selinux hook trampolines -------------------------------------------

static int (*orig_security_compute_av)(const char *, const char *,
                                       security_class_t, access_vector_t,
                                       av_decision *) = nullptr;
static int (*orig_security_compute_av_flags)(const char *, const char *,
                                             security_class_t, access_vector_t,
                                             av_decision *) = nullptr;
static int (*orig_selinux_check_access)(const char *, const char *,
                                        const char *, const char *,
                                        void *) = nullptr;

static int my_security_compute_av(const char *scon, const char *tcon,
                                  security_class_t tclass,
                                  access_vector_t requested,
                                  av_decision *avd) {
    if (is_hidden(scon) || is_hidden(tcon)) {
        fake_deny(avd);
        return 0;
    }
    if (!orig_security_compute_av) { errno = ENOSYS; return -1; }
    int r = orig_security_compute_av(scon, tcon, tclass, requested, avd);
    if (r == 0) {
        mask_hidden_bits(tclass, avd);
        mask_exact_bits(scon, tcon, tclass, avd);
    }
    return r;
}

static int my_security_compute_av_flags(const char *scon, const char *tcon,
                                        security_class_t tclass,
                                        access_vector_t requested,
                                        av_decision *avd) {
    if (is_hidden(scon) || is_hidden(tcon)) {
        fake_deny(avd);
        return 0;
    }
    if (!orig_security_compute_av_flags) { errno = ENOSYS; return -1; }
    int r = orig_security_compute_av_flags(scon, tcon, tclass, requested, avd);
    if (r == 0) {
        mask_hidden_bits(tclass, avd);
        mask_exact_bits(scon, tcon, tclass, avd);
    }
    return r;
}

static int my_selinux_check_access(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm,
                                   void *auditdata) {
    if (is_hidden(scon) || is_hidden(tcon) || is_hidden_perm(perm) ||
        is_hidden_exact(scon, tcon, tclass, perm)) {
        errno = EACCES;
        return -1;
    }
    if (orig_selinux_check_access)
        return orig_selinux_check_access(scon, tcon, tclass, perm, auditdata);
    errno = ENOSYS;
    return -1;
}

// ---- context-file interception (defeats contextExists) ------------------
//
// DirtySepolicy v2.0 writes context strings directly to kernel-backed files
// to check if SELinux types exist, bypassing libselinux APIs entirely.
// We intercept these writes and return EINVAL for hidden contexts.

#define MAX_CTX_FDS 4
static int g_ctx_fds[MAX_CTX_FDS] = {-1, -1, -1, -1};
static int g_ctx_fd_count = 0;

static inline bool is_ctx_fd(int fd) {
    for (int i = 0; i < g_ctx_fd_count; ++i)
        if (g_ctx_fds[i] == fd) return true;
    return false;
}

static inline void track_ctx_fd(int fd) {
    if (g_ctx_fd_count < MAX_CTX_FDS)
        g_ctx_fds[g_ctx_fd_count++] = fd;
}

static inline void untrack_ctx_fd(int fd) {
    for (int i = 0; i < g_ctx_fd_count; ++i) {
        if (g_ctx_fds[i] == fd) {
            g_ctx_fds[i] = g_ctx_fds[--g_ctx_fd_count];
            g_ctx_fds[g_ctx_fd_count] = -1;
            return;
        }
    }
}

static inline bool is_context_path(const char *path) {
    return path &&
           (strcmp(path, "/sys/fs/selinux/context") == 0 ||
            strcmp(path, "/proc/self/attr/current") == 0);
}

static int     (*orig_open)(const char *, int, ...) = nullptr;
static int     (*orig_openat)(int, const char *, int, ...) = nullptr;
static ssize_t (*orig_write)(int, const void *, size_t) = nullptr;
static int     (*orig_close)(int) = nullptr;

static int my_open(const char *pathname, int flags, mode_t mode) {
    int fd = orig_open ? orig_open(pathname, flags, mode) : -1;
    if (fd >= 0 && is_context_path(pathname))
        track_ctx_fd(fd);
    return fd;
}

static int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    int fd = orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
    if (fd >= 0 && is_context_path(pathname))
        track_ctx_fd(fd);
    return fd;
}

static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (g_ctx_fd_count > 0 && is_ctx_fd(fd) &&
        buf && count > 0 && count < 256) {
        char tmp[256];
        memcpy(tmp, buf, count);
        tmp[count] = '\0';
        if (is_hidden(tmp)) {
            errno = EINVAL;
            return -1;
        }
    }
    if (!orig_write) { errno = ENOSYS; return -1; }
    return orig_write(fd, buf, count);
}

static int my_close(int fd) {
    if (g_ctx_fd_count > 0 && is_ctx_fd(fd))
        untrack_ctx_fd(fd);
    return orig_close ? orig_close(fd) : -1;
}

// ---- map walking ---------------------------------------------------------

static int register_against_all_libs(zygisk::Api *api) {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) {
        LOGW("fopen(/proc/self/maps) failed: %s", strerror(errno));
        return 0;
    }
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        size_t len = strlen(path);
        if (len < 4) continue;
        if (path[len - 1] == '\n') { path[len - 1] = '\0'; len--; }
        if (len < 4) continue;
        if (strcmp(path + len - 3, ".so") != 0) continue;

        struct stat st;
        if (stat(path, &st) != 0) continue;

        api->pltHookRegister(st.st_dev, st.st_ino, "security_compute_av",
                             (void *)my_security_compute_av,
                             (void **)&orig_security_compute_av);
        api->pltHookRegister(st.st_dev, st.st_ino, "security_compute_av_flags",
                             (void *)my_security_compute_av_flags,
                             (void **)&orig_security_compute_av_flags);
        api->pltHookRegister(st.st_dev, st.st_ino, "selinux_check_access",
                             (void *)my_selinux_check_access,
                             (void **)&orig_selinux_check_access);

        api->pltHookRegister(st.st_dev, st.st_ino, "open",
                             (void *)my_open,   (void **)&orig_open);
        api->pltHookRegister(st.st_dev, st.st_ino, "openat",
                             (void *)my_openat, (void **)&orig_openat);
        api->pltHookRegister(st.st_dev, st.st_ino, "write",
                             (void *)my_write,  (void **)&orig_write);
        api->pltHookRegister(st.st_dev, st.st_ino, "close",
                             (void *)my_close,  (void **)&orig_close);
        ++n;
    }
    fclose(fp);
    return n;
}

// ---- Zygisk module --------------------------------------------------------

class DirtySepBypass : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *) override {
        install("app");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        install("server");
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv      *env = nullptr;

    void install(const char *who) {
        resolve_hidden_bits();
        int n = register_against_all_libs(api);
        if (n == 0) {
            LOGW("[%s] no .so libs found to hook", who);
            return;
        }
        if (!api->pltHookCommit()) {
            LOGW("[%s] pltHookCommit failed after registering %d libs",
                 who, n);
        } else {
            LOGI("[%s] hooks committed across %d libs", who, n);
        }
    }
};

REGISTER_ZYGISK_MODULE(DirtySepBypass)
