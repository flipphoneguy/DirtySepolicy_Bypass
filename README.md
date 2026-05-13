# DirtySepolicy Bypass

Zygisk module that defeats [LSPosed/DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) v2.0 and any detector using the same App-Zygote SELinux-probe technique.

## How it works

DirtySepolicy v2.0 uses three detection methods from inside App Zygote:

1. **`contextExists()`** — writes context strings to `/sys/fs/selinux/context` and `/proc/self/attr/current` to check if framework-injected SELinux types exist in the loaded kernel policy. This bypasses all libselinux API hooks.

2. **`checkSELinuxAccess()`** with framework contexts — probes for allow rules whose scon/tcon contains framework type names (`:magisk`, `:ksu`, `:lsposed`, etc.).

3. **`checkSELinuxAccess()`** with stock contexts — probes for allow rules between stock Android contexts that only exist because a framework injected them (e.g. `rootfs→tmpfs:associate` for Magisk, `kernel→adb_data_file:read` for KernelSU).

This module defeats all three vectors:

| Hook | Target | Method |
|---|---|---|
| `open` / `openat` / `write` / `close` | Track fds to `/sys/fs/selinux/context` and `/proc/self/attr/current`; return `EINVAL` for writes containing hidden type substrings | Defeats `contextExists()` |
| `selinux_check_access` | Substring match on scon/tcon + permission blocklist + exact-match probe table | Defeats both direct and indirect `checkSELinuxAccess()` probes |
| `security_compute_av` / `security_compute_av_flags` | Same logic via resolved numeric class/perm IDs | Defeats native-code detectors using the lower-level API |

All hooks are installed via Zygisk PLT hooking across every loaded `.so` in every app and system_server process.

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

## Exact-match probe table (indirect stock-context probes)

| scon | tcon | class | perm | Detects |
|---|---|---|---|---|
| `rootfs` | `tmpfs` | `filesystem` | `associate` | Magisk |
| `kernel` | `tmpfs` | `fifo_file` | `open` | Magisk |
| `kernel` | `adb_data_file` | `file` | `read` | KernelSU |
| `system_server` | `apk_data_file` | `file` | `execute` | LSPosed |
| `dex2oat` | `dex2oat_exec` | `file` | `execute_no_trans` | Xposed |
| `zygote` | `adb_data_file` | `dir` | `search` | ZygiskNext |

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

## Extending the bypass

If `audit.py` reports a `LEAK`:

- **For new framework type names:** Add the substring to `kHidden[]` in `jni/module.cpp` and `HOOK_BLOCKLIST` in `tools/audit.py`.
- **For new indirect stock-context probes:** Add the exact tuple to `kHiddenExact[]` in `jni/module.cpp` and `HOOK_EXACT_PROBES` in `tools/audit.py`.
- Rebuild, reflash, reboot, re-audit.

## Limitations

- **Substring blocklist.** New frameworks with novel type names need manual addition.
- **Exact-match table.** New indirect probes using stock contexts need manual addition.
- **Raw policy parsing.** A detector that reads `/sys/fs/selinux/policy` as a binary blob and parses type names directly could bypass all userspace hooks. No current detector does this.

## Compatibility

| Requirement | Notes |
|---|---|
| arm64-v8a | Pre-built for arm64. Other ABIs: rebuild from source. |
| Android >= 10 | App Zygote (the detection surface) was added in Android 10. |
| Magisk >= 24 + Zygisk | Module requires Zygisk API v5. KitsuneMask also works. |

## License

Apache 2.0
