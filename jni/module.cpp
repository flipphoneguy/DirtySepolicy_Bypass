// DirtySepolicy Bypass — Zygisk module
//
// Defeats DirtySepolicy v2.0–v2.2 detection by:
// 1. Intercepting reads/writes to /sys/fs/selinux/access to hide framework
//    allow rules and fix the avdSeqNo counter.
// 2. Intercepting writes to /sys/fs/selinux/context and /proc/self/attr/current
//    to hide framework SELinux types from contextExists() checks.
// 3. Intercepting reads from /sys/fs/selinux/status to hide evidence of
//    policy reloads (sequence/policyload counters).
// 4. PLT-hooking libselinux APIs as defense-in-depth against detectors
//    that still use the userspace library.

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

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

// ---- exact-match probes (stock contexts, framework-injected rules) ------

struct ExactProbe {
    const char *scon;
    const char *tcon;
    const char *tclass;
    const char *perm;
};

static const ExactProbe kHiddenExact[] = {
    {"u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"},
    {"u:r:kernel:s0",        "u:object_r:tmpfs:s0", "fifo_file",  "open"},
    {"u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"},
    {"u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"},
    {"u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"},
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

// ---- hidden class:perm pairs (broad perm hiding) -------------------------

struct ClassPerm { const char *cls; const char *perm; };
static const ClassPerm kHiddenClassPerms[] = {
    { "process", "execmem" },
    { nullptr, nullptr },
};

static inline bool is_hidden_perm(const char *perm) {
    if (!perm) return false;
    for (int i = 0; kHiddenClassPerms[i].perm; ++i) {
        if (strcmp(perm, kHiddenClassPerms[i].perm) == 0) return true;
    }
    return false;
}

// ---- numeric resolution via sysfs ----------------------------------------

typedef unsigned int   access_vector_t;
typedef unsigned short security_class_t;

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

static bool read_int_file(const char *path, int *out) {
    FILE *f = fopen(path, "re");
    if (!f) return false;
    char buf[32];
    bool ok = fgets(buf, sizeof(buf), f) != nullptr;
    fclose(f);
    if (!ok) return false;
    *out = atoi(buf);
    return true;
}

static bool resolve_class_perm(const char *cls, const char *perm,
                                security_class_t *out_cls, access_vector_t *out_bit) {
    char path[256];
    int cid, pid;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", cls);
    if (!read_int_file(path, &cid)) return false;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/perms/%s", cls, perm);
    if (!read_int_file(path, &pid)) return false;
    *out_cls = (security_class_t)cid;
    *out_bit = 1u << (pid - 1);
    return true;
}

static void resolve_hidden_bits() {
    if (g_bits_resolved) return;

    for (int i = 0; kHiddenClassPerms[i].cls && g_hidden_bit_count < 8; ++i) {
        security_class_t cid;
        access_vector_t pbit;
        if (resolve_class_perm(kHiddenClassPerms[i].cls, kHiddenClassPerms[i].perm,
                               &cid, &pbit)) {
            g_hidden_bits[g_hidden_bit_count++] = { cid, pbit };
        }
    }
    for (int i = 0; kHiddenExact[i].scon && g_exact_bit_count < 16; ++i) {
        security_class_t cid;
        access_vector_t pbit;
        if (resolve_class_perm(kHiddenExact[i].tclass, kHiddenExact[i].perm,
                               &cid, &pbit)) {
            g_exact_bits[g_exact_bit_count++] = {
                kHiddenExact[i].scon, kHiddenExact[i].tcon, cid, pbit
            };
        }
    }

    g_bits_resolved = true;
}

// ---- kernel version detection -------------------------------------------

static bool g_new_kernel = false;

static void detect_kernel_version() {
    struct utsname uts;
    if (uname(&uts) != 0) return;
    int major = 0, minor = 0;
    sscanf(uts.release, "%d.%d", &major, &minor);
    g_new_kernel = (major > 6 || (major == 6 && minor >= 10));
}

// ---- fd tracking --------------------------------------------------------

enum FdType : unsigned char {
    FD_NONE = 0,
    FD_CONTEXT,
    FD_ACCESS,
    FD_STATUS,
};

struct TrackedFd {
    int fd;
    FdType type;
    char scon[256];
    char tcon[256];
    unsigned int tclass;
    bool has_query;
};

#define MAX_TRACKED 16
static TrackedFd g_tracked[MAX_TRACKED];
static int g_tracked_count = 0;

static TrackedFd *find_tracked(int fd) {
    for (int i = 0; i < g_tracked_count; ++i)
        if (g_tracked[i].fd == fd) return &g_tracked[i];
    return nullptr;
}

static void track_fd(int fd, FdType type) {
    for (int i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i].type = type;
            g_tracked[i].scon[0] = '\0';
            g_tracked[i].tcon[0] = '\0';
            g_tracked[i].tclass = 0;
            g_tracked[i].has_query = false;
            return;
        }
    }
    if (g_tracked_count >= MAX_TRACKED) return;
    auto *t = &g_tracked[g_tracked_count++];
    t->fd = fd;
    t->type = type;
    t->scon[0] = '\0';
    t->tcon[0] = '\0';
    t->tclass = 0;
    t->has_query = false;
}

static void untrack_fd(int fd) {
    for (int i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i] = g_tracked[--g_tracked_count];
            return;
        }
    }
}

static const char *selinuxfs_name(const char *path) {
    if (strncmp(path, "/sys/fs/selinux/", 16) == 0) return path + 16;
    if (strncmp(path, "/selinux/", 9) == 0)         return path + 9;
    return nullptr;
}

static FdType classify_path(const char *path) {
    if (!path) return FD_NONE;

    const char *name = selinuxfs_name(path);
    if (name) {
        if (strcmp(name, "access") == 0)  return FD_ACCESS;
        if (strcmp(name, "status") == 0)  return FD_STATUS;
        if (strcmp(name, "context") == 0 ||
            strcmp(name, "create") == 0 ||
            strcmp(name, "member") == 0 ||
            strcmp(name, "relabel") == 0 ||
            strcmp(name, "user") == 0 ||
            strcmp(name, "validatetrans") == 0) return FD_CONTEXT;
    }

    if (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/attr/"))
        return FD_CONTEXT;

    return FD_NONE;
}

// ---- access query parsing and response patching -------------------------

static void parse_access_query(TrackedFd *tfd, const char *query) {
    const char *sp1 = strchr(query, ' ');
    if (!sp1) return;
    size_t len = sp1 - query;
    if (len >= sizeof(tfd->scon)) len = sizeof(tfd->scon) - 1;
    memcpy(tfd->scon, query, len);
    tfd->scon[len] = '\0';

    const char *p = sp1 + 1;
    const char *sp2 = strchr(p, ' ');
    if (!sp2) return;
    len = sp2 - p;
    if (len >= sizeof(tfd->tcon)) len = sizeof(tfd->tcon) - 1;
    memcpy(tfd->tcon, p, len);
    tfd->tcon[len] = '\0';

    tfd->tclass = (unsigned int)strtoul(sp2 + 1, nullptr, 10);
    tfd->has_query = true;
}

static ssize_t patch_access_response(TrackedFd *tfd, char *buf,
                                     ssize_t ret, size_t bufsize) {
    if (ret <= 0 || (size_t)ret >= bufsize) return ret;

    char tmp[128];
    if ((size_t)ret >= sizeof(tmp)) return ret;
    memcpy(tmp, buf, ret);
    tmp[ret] = '\0';

    unsigned int allowed, decided, auditallow, auditdeny, flags, seqno;
    if (sscanf(tmp, "%x %x %x %x %u %x",
               &allowed, &decided, &auditallow, &auditdeny, &seqno, &flags) != 6) {
        return ret;
    }

    for (int i = 0; i < g_hidden_bit_count; ++i) {
        if (g_hidden_bits[i].cls_id == (security_class_t)tfd->tclass) {
            allowed    &= ~g_hidden_bits[i].perm_bit;
            auditallow &= ~g_hidden_bits[i].perm_bit;
        }
    }

    for (int i = 0; i < g_exact_bit_count; ++i) {
        if (g_exact_bits[i].cls_id == (security_class_t)tfd->tclass &&
            strcmp(tfd->scon, g_exact_bits[i].scon) == 0 &&
            strcmp(tfd->tcon, g_exact_bits[i].tcon) == 0) {
            allowed    &= ~g_exact_bits[i].perm_bit;
            auditallow &= ~g_exact_bits[i].perm_bit;
        }
    }

    seqno = 1;

    int newlen = snprintf(buf, bufsize, "%x %x %x %x %u %x",
                          allowed, decided, auditallow, auditdeny, seqno, flags);
    if (newlen < 0 || (size_t)newlen >= bufsize) return ret;
    return newlen;
}

// ---- status patching ----------------------------------------------------

static void patch_status(void *buf, ssize_t len) {
    if (len < 20) return;
    auto *p = (unsigned char *)buf;
    unsigned int seq, pload;
    if (g_new_kernel) {
        seq = 4;  pload = 1;
    } else {
        seq = 0;  pload = 0;
    }
    memcpy(p + 4,  &seq,   sizeof(seq));
    memcpy(p + 12, &pload, sizeof(pload));
}

// ---- libselinux ABI (defense-in-depth hooks) ----------------------------

struct av_decision {
    access_vector_t allowed;
    access_vector_t decided;
    access_vector_t auditallow;
    access_vector_t auditdeny;
    unsigned int    seqno;
    unsigned int    flags;
};

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
    avd->seqno      = 1;
    avd->flags      = 0;
}

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
        if (avd) avd->seqno = 1;
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
        if (avd) avd->seqno = 1;
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

// ---- file I/O hooks -----------------------------------------------------

static int     (*orig_open)(const char *, int, ...) = nullptr;
static int     (*orig_openat)(int, const char *, int, ...) = nullptr;
static ssize_t (*orig_write)(int, const void *, size_t) = nullptr;
static ssize_t (*orig_read)(int, void *, size_t) = nullptr;
static ssize_t (*orig_pread64)(int, void *, size_t, off64_t) = nullptr;
static int     (*orig_close)(int) = nullptr;

static int my_open(const char *pathname, int flags, mode_t mode) {
    int fd = orig_open ? orig_open(pathname, flags, mode) : -1;
    if (fd >= 0) {
        FdType type = classify_path(pathname);
        if (type != FD_NONE)
            track_fd(fd, type);
    }
    return fd;
}

static int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    int fd = orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
    if (fd >= 0) {
        FdType type = classify_path(pathname);
        if (type != FD_NONE)
            track_fd(fd, type);
    }
    return fd;
}

static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (g_tracked_count > 0 && buf && count > 0 && count < 512) {
        auto *tfd = find_tracked(fd);
        if (tfd) {
            char tmp[512];
            memcpy(tmp, buf, count);
            tmp[count] = '\0';

            if (tfd->type == FD_CONTEXT || tfd->type == FD_ACCESS) {
                if (is_hidden(tmp)) {
                    errno = EINVAL;
                    return -1;
                }
            }

            if (tfd->type == FD_ACCESS)
                parse_access_query(tfd, tmp);
        }
    }
    if (!orig_write) { errno = ENOSYS; return -1; }
    return orig_write(fd, buf, count);
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    if (!orig_read) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_read(fd, buf, count);
    if (ret <= 0 || g_tracked_count == 0) return ret;

    auto *tfd = find_tracked(fd);
    if (!tfd) return ret;

    if (tfd->type == FD_ACCESS && tfd->has_query) {
        ret = patch_access_response(tfd, (char *)buf, ret, count);
        tfd->has_query = false;
    } else if (tfd->type == FD_STATUS) {
        patch_status(buf, ret);
    }

    return ret;
}

static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    if (!orig_pread64) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_pread64(fd, buf, count, offset);
    if (ret <= 0 || g_tracked_count == 0) return ret;

    auto *tfd = find_tracked(fd);
    if (!tfd) return ret;

    if (tfd->type == FD_ACCESS && tfd->has_query) {
        ret = patch_access_response(tfd, (char *)buf, ret, count);
        tfd->has_query = false;
    } else if (tfd->type == FD_STATUS) {
        patch_status(buf, ret);
    }

    return ret;
}

static int my_close(int fd) {
    if (g_tracked_count > 0)
        untrack_fd(fd);
    return orig_close ? orig_close(fd) : -1;
}

// ---- map walking --------------------------------------------------------

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

        api->pltHookRegister(st.st_dev, st.st_ino, "open",
                             (void *)my_open,   (void **)&orig_open);
        api->pltHookRegister(st.st_dev, st.st_ino, "openat",
                             (void *)my_openat, (void **)&orig_openat);
        api->pltHookRegister(st.st_dev, st.st_ino, "write",
                             (void *)my_write,  (void **)&orig_write);
        api->pltHookRegister(st.st_dev, st.st_ino, "read",
                             (void *)my_read,   (void **)&orig_read);
        api->pltHookRegister(st.st_dev, st.st_ino, "pread64",
                             (void *)my_pread64, (void **)&orig_pread64);
        api->pltHookRegister(st.st_dev, st.st_ino, "close",
                             (void *)my_close,  (void **)&orig_close);

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

// ---- Zygisk module ------------------------------------------------------

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
        detect_kernel_version();
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
