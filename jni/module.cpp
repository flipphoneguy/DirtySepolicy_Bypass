// DirtySepolicy Bypass — Zygisk module
//
// PLT-hooks selinux_check_access / security_compute_av(_flags) in every
// loaded shared object. When a probe's scon or tcon contains the name of a
// hidden SELinux type the hook synthesises a "denied" result locally without
// reaching the kernel's selinuxfs. Every other access check passes through
// to the real libselinux unchanged.

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
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

// Substrings that, when seen in scon or tcon, cause the hook to lie.
// Patterns are prefix-shaped so they catch every *_file, *_exec, *_data,
// *_service, *32, etc. variant a fork might introduce.
//
// `:su:` is intentionally exact (trailing colon) so it only hides the AOSP
// `u:r:su:s0` / `u:object_r:su_*:s0` family — broader matching would catch
// stock type names ending in `_su`.
static const char *const kHidden[] = {
    // Magisk + forks
    ":magisk",     ":kitsune",    ":apatch",
    // KernelSU
    ":ksu",        ":kernelsu",
    // Xposed family
    ":lsposed",    ":xposed",     ":riru",
    // adb_root patch and adbroot_* siblings
    ":adbroot",
    // SuperSU / supolicy / AOSP su
    ":supersu",    ":supolicy",   ":su:",
    // Generic zygisk artifact name some forks use
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

// Permissions we lie about regardless of which domains the probe names.
// These are "policy hygiene" indicators (e.g. system_server can execmem)
// that hygiene-style detectors flag. Kernel enforcement is unchanged —
// only userspace probers see the lie.
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

// To also hide the same probe when made via the lower-level
// security_compute_av(_flags) ABI (which takes numeric class/perm IDs
// instead of strings), we resolve each (class_name, perm_name) pair to its
// numeric (class_id, perm_bit) at hook-install time, then mask the bit out
// of the returned allowed mask on subsequent calls.

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
static bool        g_bits_resolved = false;

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

static void fake_deny(av_decision *avd) {
    if (!avd) return;
    avd->allowed    = 0;
    avd->decided    = ~0u;
    avd->auditallow = 0;
    avd->auditdeny  = ~0u;
    avd->seqno      = 0;
    avd->flags      = 0;
}

// ---- hook trampolines ----------------------------------------------------

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
    if (r == 0) mask_hidden_bits(tclass, avd);
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
    if (r == 0) mask_hidden_bits(tclass, avd);
    return r;
}

static int my_selinux_check_access(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm,
                                   void *auditdata) {
    if (is_hidden(scon) || is_hidden(tcon) || is_hidden_perm(perm)) {
        errno = EACCES;
        return -1;
    }
    if (orig_selinux_check_access)
        return orig_selinux_check_access(scon, tcon, tclass, perm, auditdata);
    errno = ENOSYS;
    return -1;
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
