#!/usr/bin/env python3
"""
SELinux detection-surface audit.

Enumerates every SELinux signal on this device that a current or future
detector (DirtySepolicy-style: probes via SELinux.checkSELinuxAccess or
direct kernel file writes from inside app_zygote) could use to catch
your root/hooking framework, and reports whether the installed Zygisk
bypass module hides each one.

Output columns:
  PROBE           — human label
  RULE-EXISTS     — does the kernel's loaded policy say "allowed=true"?
  HOOK-HIDES      — would our module's hooks mask this probe?
  STATUS          — BLOCKED / LEAK / absent

LEAK means: rule present in the kernel + hook does NOT match — a detector
hardcoding this probe would catch you. Each LEAK is an action item.
"""

import ctypes
import os
import re
import sys

# ---------- libselinux ----------------------------------------------------

LIBSEL = ctypes.CDLL("/system/lib64/libselinux.so")
LIBSEL.selinux_check_access.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_void_p,
]
LIBSEL.selinux_check_access.restype = ctypes.c_int

LIBSEL.security_check_context.argtypes = [ctypes.c_char_p]
LIBSEL.security_check_context.restype = ctypes.c_int


def kernel_allows(scon, tcon, tclass, perm):
    """Returns True iff the loaded SELinux policy allows scon->tcon for tclass/perm."""
    return LIBSEL.selinux_check_access(
        scon.encode(), tcon.encode(),
        tclass.encode(), perm.encode(), None,
    ) == 0


def context_exists(context):
    """Returns True iff the SELinux context type exists in the loaded policy."""
    return LIBSEL.security_check_context(context.encode()) == 0


# ---------- module blocklist (must match jni/module.cpp kHidden[]) --------

HOOK_BLOCKLIST = [
    ":magisk", ":kitsune", ":apatch",
    ":ksu", ":kernelsu",
    ":lsposed", ":xposed", ":riru",
    ":adbroot",
    ":supersu", ":supolicy", ":su:",
    ":zygisk",
]


HOOK_HIDDEN_PERMS = [
    "execmem",
]

HOOK_EXACT_PROBES = [
    ("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"),
    ("u:r:kernel:s0",        "u:object_r:tmpfs:s0", "fifo_file",  "open"),
    ("u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"),
    ("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"),
    ("u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"),
    ("u:r:zygote:s0",        "u:object_r:adb_data_file:s0", "dir",  "search"),
]


def hook_would_hide(scon, tcon, tclass=None, perm=None):
    """Mirrors is_hidden() + is_hidden_perm() + is_hidden_exact() in jni/module.cpp."""
    for s in HOOK_BLOCKLIST:
        if s in scon or s in tcon:
            return True
    if perm and perm in HOOK_HIDDEN_PERMS:
        return True
    if tclass and perm:
        for es, et, ec, ep in HOOK_EXACT_PROBES:
            if scon == es and tcon == et and tclass == ec and perm == ep:
                return True
    return False


def hook_would_hide_context(context):
    """Mirrors is_hidden() check on context strings written to kernel files."""
    for s in HOOK_BLOCKLIST:
        if s in context:
            return True
    return False


# ---------- known probe surface ------------------------------------------

# (label, scon, tcon, tclass, perm)
KNOWN_ACCESS_PROBES = [
    # --- current DirtySepolicy v2.0 probes ---
    ("v2 : system_server execmem", "u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem"),
    ("v2 : AOSP-su transition",    "u:r:shell:s0",         "u:r:su:s0",            "process", "transition"),
    ("v2 : adb_root binder",       "u:r:adbd:s0",          "u:r:adbroot:s0",       "binder",  "call"),
    ("v2 : Magisk file read",      "u:r:untrusted_app:s0", "u:object_r:magisk_file:s0", "file", "read"),
    ("v2 : Magisk rootfs→tmpfs",   "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0",  "filesystem", "associate"),
    ("v2 : Magisk kernel→tmpfs",   "u:r:kernel:s0",        "u:object_r:tmpfs:s0",  "fifo_file", "open"),
    ("v2 : KSU kernel→adb_data",   "u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"),
    ("v2 : KSU file read",         "u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file", "read"),
    ("v2 : LSPosed file read",     "u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read"),
    ("v2 : LSPosed apk execute",   "u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"),
    ("v2 : Xposed data read",      "u:r:untrusted_app:s0", "u:object_r:xposed_data:s0", "file", "read"),
    ("v2 : Xposed dex2oat exec",   "u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans"),
    ("v2 : ZygiskNext dir search",  "u:r:zygote:s0",       "u:object_r:adb_data_file:s0", "dir", "search"),

    # --- plausible future probes ---
    ("future : magisk32 binder",      "u:r:untrusted_app:s0", "u:r:magisk32:s0",               "binder", "call"),
    ("future : magisk_log_file read", "u:r:untrusted_app:s0", "u:object_r:magisk_log_file:s0", "file",   "read"),
    ("future : APatch binder",        "u:r:untrusted_app:s0", "u:r:apatch:s0",                 "binder", "call"),
    ("future : KitsuneMask binder",   "u:r:untrusted_app:s0", "u:r:kitsune:s0",                "binder", "call"),
    ("future : Riru file",            "u:r:untrusted_app:s0", "u:object_r:riru_file:s0",       "file",   "read"),
    ("future : SuperSU binder",       "u:r:untrusted_app:s0", "u:r:supersu:s0",                "binder", "call"),
    ("future : Zygisk-generic file",  "u:r:untrusted_app:s0", "u:object_r:zygisk_file:s0",     "file",   "read"),
]

# (label, context) — contextExists() probes from DirtySepolicy v2.0
KNOWN_CONTEXT_PROBES = [
    ("v2 ctx : adbroot",       "u:r:adbroot:s0"),
    ("v2 ctx : magisk",        "u:r:magisk:s0"),
    ("v2 ctx : magisk_file",   "u:object_r:magisk_file:s0"),
    ("v2 ctx : ksu",           "u:r:ksu:s0"),
    ("v2 ctx : ksu_file",      "u:object_r:ksu_file:s0"),
    ("v2 ctx : lsposed_file",  "u:object_r:lsposed_file:s0"),
    ("v2 ctx : xposed_data",   "u:object_r:xposed_data:s0"),
    ("v2 ctx : xposed_file",   "u:object_r:xposed_file:s0"),
]


# ---------- policy type discovery ----------------------------------------

POLICY = "/sys/fs/selinux/policy"

SUSPICIOUS = [
    "magisk", "ksu", "kernelsu", "lsposed", "xposed", "riru",
    "supersu", "zygisk", "apatch", "shamiko", "kitsune", "adbroot",
    "supolicy", "su_daemon",
]

STOCK_FP = {
    "su",
}


def discover_types():
    try:
        blob = open(POLICY, "rb").read()
    except PermissionError:
        print(f"WARN: cannot read {POLICY} (need root for full enumeration)",
              file=sys.stderr)
        return set()
    ids = set(m.decode("ascii", errors="ignore")
              for m in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{2,63}", blob))
    return ids


def suspicious_types(ids):
    out = []
    for tn in sorted(ids):
        if tn in STOCK_FP:
            continue
        low = tn.lower()
        if any(s in low for s in SUSPICIOUS):
            out.append(tn)
    return out


# ---------- presentation -------------------------------------------------

def color(s, c):
    if not sys.stdout.isatty():
        return s
    codes = {"red": 31, "green": 32, "yellow": 33, "cyan": 36, "dim": 90}
    return f"\033[{codes[c]}m{s}\033[0m"


def status_of(rule_ok, hook_ok):
    if rule_ok and hook_ok:
        return color("BLOCKED", "green")
    if rule_ok and not hook_ok:
        return color("LEAK", "red")
    if not rule_ok and hook_ok:
        return color("(over-block)", "dim")
    return color("absent", "dim")


def main():
    print("=" * 78)
    print("SELinux detection-surface audit (DirtySepolicy v2.0)")
    print("=" * 78)
    print()

    leaks = []

    # --- Section 1: context-existence probes ---
    print(f"{'CONTEXT PROBE':<36} {'EXISTS':<6} {'HOOK':<6} STATUS")
    print("-" * 78)
    for label, ctx in KNOWN_CONTEXT_PROBES:
        exists = context_exists(ctx)
        hides = hook_would_hide_context(ctx)
        st = status_of(exists, hides)
        print(f"{label:<36} {('yes' if exists else 'no'):<6} "
              f"{('hide' if hides else '-'):<6} {st}")
        if exists and not hides:
            leaks.append((label, ctx, None, None, None))

    # --- Section 2: access-check probes ---
    print()
    print(f"{'ACCESS PROBE':<36} {'RULE':<6} {'HOOK':<6} STATUS")
    print("-" * 78)
    for label, scon, tcon, tclass, perm in KNOWN_ACCESS_PROBES:
        ok = kernel_allows(scon, tcon, tclass, perm)
        hk = hook_would_hide(scon, tcon, tclass, perm)
        st = status_of(ok, hk)
        print(f"{label:<36} {('yes' if ok else 'no'):<6} "
              f"{('hide' if hk else '-'):<6} {st}")
        if ok and not hk:
            leaks.append((label, scon, tcon, tclass, perm))

    # --- Section 3: type enumeration ---
    print()
    print("Loaded-policy enumeration (suspicious types in /sys/fs/selinux/policy):")
    print("-" * 78)
    ids = discover_types()
    if not ids:
        print("  (cannot read policy without root -- rerun with: su -c 'python3 ...')")
    else:
        sus = suspicious_types(ids)
        if not sus:
            print("  no framework-shaped types found")
        else:
            for tn in sus:
                covered = any(s.strip(":") in tn for s in HOOK_BLOCKLIST)
                marker = color("hidden", "green") if covered else color("EXPOSED", "red")
                print(f"  {tn:<40} {marker}")

    # --- Section 4: summary ---
    print()
    print("=" * 78)
    print("Summary")
    print("=" * 78)
    if leaks:
        print(f"{color('LEAKS', 'red')}: {len(leaks)} probe(s) the kernel confirms exist")
        print("        AND our hook would NOT mask. Action: extend the bypass.")
        for entry in leaks:
            label = entry[0]
            print(f"  - {label}")
            if entry[2]:
                print(f"      scon={entry[1]}  tcon={entry[2]}")
                print(f"      tclass={entry[3]}  perm={entry[4]}")
            else:
                print(f"      context={entry[1]}")
    else:
        print(color("No leaks among known probes.", "green"))

    print()
    print("Notes:")
    print(" - Context probes test the open/write/close hooks that intercept")
    print("   writes to /sys/fs/selinux/context and /proc/self/attr/current.")
    print(" - Access probes test both substring matching and exact-match tables.")
    print(" - Type enumeration is a FORWARD scan: any *new* probe a future detector")
    print("   might hardcode against the listed types would need to be added to")
    print("   the hook blocklist or exact-match table.")
    print(" - This audit runs in a shell process (no Zygisk hook). To verify the")
    print("   hook is actually live in app_zygote, run DirtySepolicy itself.")


if __name__ == "__main__":
    main()
