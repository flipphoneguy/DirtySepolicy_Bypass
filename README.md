# DirtySepolicy Bypass

Zygisk module that defeats [LSPosed/DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) and any detector using the same App-Zygote SELinux-probe technique.

## How it works

DirtySepolicy probes the kernel's loaded SELinux policy from inside App Zygote, looking for type names injected by root/hooking frameworks (Magisk, KernelSU, LSPosed, etc.). If the probe returns "allowed", the framework is detected.

This module installs PLT hooks on three libselinux entry points in every loaded `.so`:

- `selinux_check_access`
- `security_compute_av`
- `security_compute_av_flags`

When a call's `scon` or `tcon` contains a known framework substring, the hook returns a synthetic "denied" result without forwarding to the kernel. All other access checks pass through unchanged.

## Repository layout

```
DirtySepolicy_Bypass/
├── README.md              # This file
├── .gitignore
├── module/                # Flashable Magisk module structure
│   ├── module.prop        # Module metadata (id, name, version)
│   ├── customize.sh       # Installer: validates Magisk version, Zygisk, ABI
│   ├── META-INF/          # Standard Magisk zip boilerplate
│   └── zygisk/            # Compiled .so goes here (not tracked — see Releases)
├── jni/                   # Native source code
│   ├── module.cpp         # Hook implementation (blocklist + PLT hook logic)
│   ├── zygisk.hpp         # Zygisk API v5 header (from upstream Magisk)
│   ├── Android.mk         # NDK build config
│   └── Application.mk    # NDK app-level config (ABI, STL, optimization)
└── tools/
    └── audit.py           # Detection-surface audit script (run on-device)
```

## Hidden type patterns

| Pattern | Catches |
|---|---|
| `:magisk` | `magisk`, `magisk_file`, `magisk_log_file`, `magisk32`, ... |
| `:kitsune` | KitsuneMask types |
| `:apatch` | APatch types |
| `:ksu` / `:kernelsu` | KernelSU types |
| `:lsposed` | `lsposed_file`, any `lsposed_*` |
| `:xposed` | `xposed_data`, `xposed_file`, any `xposed_*` |
| `:riru` | `riru_file`, any `riru_*` |
| `:adbroot` | `adbroot`, `adbroot_exec`, `adbroot_data_file` |
| `:supersu` / `:supolicy` | SuperSU legacy types |
| `:su:` | AOSP `u:r:su:s0` (exact — trailing colon avoids false positives) |
| `:zygisk` | Any generic `zygisk_*` artifact |

## Build

Compile natively on Termux (arm64):

```sh
cd jni

aarch64-linux-android-clang++ \
  -std=c++17 -fno-exceptions -fno-rtti \
  -fPIC -shared -O2 \
  -fvisibility=hidden -fvisibility-inlines-hidden \
  -fdata-sections -ffunction-sections \
  -nostdlib++ \
  -Wall -Wextra \
  -Wl,--hash-style=both \
  -Wl,--gc-sections \
  -Wl,-z,lazy \
  -Wl,-z,norelro \
  -Wl,-soname,libdirtysepbypass.so \
  -o ../module/zygisk/arm64-v8a.so \
  module.cpp -llog

patchelf --remove-rpath ../module/zygisk/arm64-v8a.so
```

Package the flashable zip:

```sh
cd module
zip -r9 ../dirtysepbypass.zip module.prop customize.sh META-INF zygisk
```

## Install

Via Magisk app: **Modules > Install from storage > select `dirtysepbypass.zip` > Reboot.**

Or from a root shell:

```sh
su -c "magisk --install-module /sdcard/dirtysepbypass.zip"
su -c reboot
```

## Verify

1. Run DirtySepolicy — should show "OK: no dirty sepolicy found" with zero warnings.

2. Check hook logs:
   ```sh
   su -c "logcat -d -s DirtySepBypass"
   ```

3. Run the audit tool:
   ```sh
   su -c "python3 tools/audit.py"
   ```

## Extending the blocklist

If `audit.py` reports a `LEAK` or `EXPOSED` type:

1. Add the substring to `kHidden[]` in `jni/module.cpp`
2. Add the same substring to `HOOK_BLOCKLIST` in `tools/audit.py`
3. Rebuild, reflash, reboot, re-audit

## Limitations

- **Substring blocklist.** New frameworks with novel type names need manual addition.
- **Hygiene probes hidden.** `system_server execmem` (a stock-policy property, not a root indicator) is denied to userspace probers so hygiene-style detectors report a clean result. Kernel enforcement is unchanged.

## Compatibility

| Requirement | Notes |
|---|---|
| arm64-v8a | Pre-built for arm64. Other ABIs: rebuild from source. |
| Android >= 10 | App Zygote (the detection surface) was added in Android 10. |
| Magisk >= 24 + Zygisk | Module requires Zygisk API v5. KitsuneMask also works. |

## License

Apache 2.0
