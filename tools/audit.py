#!/usr/bin/env python3
"""
SELinux detection-surface audit.

Enumerates every SELinux signal on this device that a current or future
detector (DirtySepolicy-style: probes via SELinux.checkSELinuxAccess from
inside app_zygote) could use to catch your root/hooking framework, and
reports whether the installed Zygisk bypass module hides each one.

Output columns:
  PROBE           — human label
  RULE-EXISTS     — does the kernel's loaded policy say "allowed=true"?
  HOOK-HIDES      — would our module's hidden-type substring blocklist
                    cause selinux_check_access to return false?
  STATUS          — BLOCKED / LEAK / absent

LEAK means: rule present in the kernel + hook does NOT match — a detector
hardcoding this probe would catch you. Each LEAK is an action item.

This script runs in a regular shell context, so:
  RULE-EXISTS  = ground truth (kernel policy as loaded)
  HOOK-HIDES   = simulation against the blocklist baked into the module .so

The two together tell you: where are you exposed, where are you covered,
and where the hook over-blocks (rule absent but hook would still match).
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


def kernel_allows(scon, tcon, tclass, perm):
    """Returns True iff the loaded SELinux policy allows scon->tcon for tclass/perm."""
    return LIBSEL.selinux_check_access(
        scon.encode(), tcon.encode(),
        tclass.encode(), perm.encode(), None,
    ) == 0


# ---------- module blocklist (must match jni/module.cpp kHidden[]) --------

HOOK_BLOCKLIST = [
    # Magisk + forks
    ":magisk", ":kitsune", ":apatch",
    # KernelSU
    ":ksu", ":kernelsu",
    # Xposed family
    ":lsposed", ":xposed", ":riru",
    # adb_root and siblings
    ":adbroot",
    # SuperSU / supolicy / AOSP su
    ":supersu", ":supolicy", ":su:",
    # Generic zygisk
    ":zygisk",
]


HOOK_HIDDEN_PERMS = [
    "execmem",
]


def hook_would_hide(scon, tcon, perm=None):
    """Mirrors is_hidden() + is_hidden_perm() in jni/module.cpp."""
    for s in HOOK_BLOCKLIST:
        if s in scon or s in tcon:
            return True
    if perm and perm in HOOK_HIDDEN_PERMS:
        return True
    return False


# ---------- known probe surface ------------------------------------------

# (label, scon, tcon, tclass, perm)
KNOWN_PROBES = [
    # --- current DirtySepolicy probes (AppZygote.java) ---
    ("DirtySepolicy : Magisk",        "u:r:untrusted_app:s0", "u:r:magisk:s0",                "binder", "call"),
    ("DirtySepolicy : KernelSU",      "u:r:untrusted_app:s0", "u:object_r:ksu_file:s0",       "file",   "read"),
    ("DirtySepolicy : LSPosed",       "u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0",   "file",   "read"),
    ("DirtySepolicy : Xposed",        "u:r:untrusted_app:s0", "u:object_r:xposed_data:s0",    "file",   "read"),
    ("DirtySepolicy : adb_root",      "u:r:adbd:s0",          "u:r:adbroot:s0",               "binder", "call"),
    ("DirtySepolicy : AOSP-su",       "u:r:shell:s0",         "u:r:su:s0",                    "process","transition"),
    ("DirtySepolicy : ZygiskNext",    "u:r:zygote:s0",        "u:object_r:adb_data_file:s0",  "dir",    "search"),

    # --- policy hygiene (device-policy, not framework-specific) ---
    ("hygiene : system_server execmem","u:r:system_server:s0","u:r:system_server:s0",         "process","execmem"),
    ("hygiene : neverallow (fsck)",   "u:r:fsck_untrusted:s0","u:r:fsck_untrusted:s0",        "capability","sys_admin"),

    # --- plausible future probes against Magisk ---
    ("future : magisk32 binder",      "u:r:untrusted_app:s0", "u:r:magisk32:s0",              "binder", "call"),
    ("future : magisk_file read",     "u:r:untrusted_app:s0", "u:object_r:magisk_file:s0",    "file",   "read"),
    ("future : magisk_log_file read", "u:r:untrusted_app:s0", "u:object_r:magisk_log_file:s0","file",   "read"),
    ("future : zygote->magisk dir",   "u:r:zygote:s0",        "u:object_r:magisk_file:s0",   "dir",    "search"),
    ("future : magisk transition",    "u:r:init:s0",          "u:r:magisk:s0",                "process","transition"),

    # --- plausible future probes against other frameworks ---
    ("future : APatch",               "u:r:untrusted_app:s0", "u:r:apatch:s0",                "binder", "call"),
    ("future : KitsuneMask",          "u:r:untrusted_app:s0", "u:r:kitsune:s0",               "binder", "call"),
    ("future : Riru file",            "u:r:untrusted_app:s0", "u:object_r:riru_file:s0",      "file",   "read"),
    ("future : SuperSU",              "u:r:untrusted_app:s0", "u:r:supersu:s0",               "binder", "call"),
    ("future : Zygisk-generic file",  "u:r:untrusted_app:s0", "u:object_r:zygisk_file:s0",    "file",   "read"),
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
    """Read /sys/fs/selinux/policy and pull out ASCII identifiers."""
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
    print("=" * 72)
    print("SELinux detection-surface audit (futureproof)")
    print("=" * 72)
    print()

    # --- Section 1: known probe matrix ---
    print(f"{'PROBE':<36} {'RULE':<6} {'HOOK':<6} STATUS")
    print("-" * 72)
    leaks = []
    overblocks = []
    for label, scon, tcon, tclass, perm in KNOWN_PROBES:
        ok = kernel_allows(scon, tcon, tclass, perm)
        hk = hook_would_hide(scon, tcon, perm)
        st = status_of(ok, hk)
        print(f"{label:<36} {('yes' if ok else 'no'):<6} "
              f"{('hide' if hk else '-'):<6} {st}")
        if ok and not hk:
            leaks.append((label, scon, tcon, tclass, perm))
        if not ok and hk:
            overblocks.append((label, scon, tcon))

    # --- Section 2: type enumeration ---
    print()
    print("Loaded-policy enumeration (suspicious types in /sys/fs/selinux/policy):")
    print("-" * 72)
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

    # --- Section 3: summary ---
    print()
    print("=" * 72)
    print("Summary")
    print("=" * 72)
    if leaks:
        print(f"{color('LEAKS', 'red')}: {len(leaks)} probe(s) the kernel would say YES to")
        print("        AND our hook would NOT mask. Action: extend HOOK_BLOCKLIST.")
        for label, scon, tcon, tclass, perm in leaks:
            print(f"  - {label}")
            print(f"      scon={scon}")
            print(f"      tcon={tcon}")
            print(f"      tclass={tclass} perm={perm}")
    else:
        print(color("No leaks among known probes.", "green"))

    if overblocks:
        print()
        print(f"{color('OVER-BLOCK', 'yellow')}: {len(overblocks)} probe(s) absent from kernel "
              f"but matched by hook blocklist. Harmless -- just unused entries.")

    print()
    print("Notes:")
    print(" - Policy-hygiene probes (system_server execmem) are hidden via the")
    print("   permission blocklist (HOOK_HIDDEN_PERMS). Kernel enforcement is")
    print("   unchanged — only userspace probers see the denial.")
    print(" - Type enumeration is a FORWARD scan: any *new* probe a future detector")
    print("   might hardcode against the listed types would be caught by extending")
    print("   the hook blocklist with the matching substring.")
    print(" - This audit runs in a shell process (no Zygisk hook). To verify the")
    print("   hook is actually live in app_zygote, run DirtySepolicy itself.")


if __name__ == "__main__":
    main()
