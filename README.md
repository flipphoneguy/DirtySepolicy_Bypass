# DirtySepolicy Bypass

Zygisk module that defeats [LSPosed/DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) v2.0–v2.2 and any detector using the same App-Zygote SELinux-probe technique.

## How it works

DirtySepolicy v2.2 uses four detection methods from inside App Zygote:

1. **`contextExists()`** — writes context strings to `/sys/fs/selinux/context`, queries `/sys/fs/selinux/access`, and falls back to `/proc/self/attr/current` to check if framework-injected SELinux types exist in the loaded kernel policy.

2. **`checkSELinuxAccess()`** via kernel — resolves class/perm names from `/sys/fs/selinux/class/` and queries `/sys/fs/selinux/access` directly, bypassing libselinux entirely.

3. **`readStatus()` / `avdSeqNo`** — reads `/sys/fs/selinux/status` for sequence/policyload counters and reads `seqno` from `/sys/fs/selinux/access` responses to detect policy reloads.

4. **Indirect stock-context probes** — checks allow rules between stock Android contexts that only exist because a framework injected them (e.g. `rootfs→tmpfs:associate` for Magisk).

This module defeats all four vectors:

| Hook | Target | Method |
|---|---|---|
| `write` on `/sys/fs/selinux/access` | Block writes containing hidden context substrings; stash query for read patching | Defeats `contextExists()` access fallback and hidden-context `checkSELinuxAccess()` |
| `read` on `/sys/fs/selinux/access` | Parse kernel response, mask hidden permission bits, mask exact-probe bits, rewrite `seqno` to 1 | Defeats `checkSELinuxAccess()` and `avdSeqNo` detection |
| `read` on `/sys/fs/selinux/status` | Patch `sequence` and `policyload` fields to clean-boot values based on kernel version | Defeats `readStatus()` policy-reload detection |
| `write` on `/sys/fs/selinux/context` and `/proc/self/attr/current` | Return `EINVAL` for writes containing hidden type substrings | Defeats `contextExists()` first and last checks |
| `selinux_check_access` / `security_compute_av` | Same logic via libselinux API (defense-in-depth for older detectors) | Defeats v2.0/v2.1 and any libselinux-based detector |

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
- **Kernel-level counters.** The status and seqno patches assume specific clean-boot values (kernel < 6.10: seq=0/policyload=0; kernel >= 6.10: seq=4/policyload=1). Non-standard boot sequences or OEM policy loaders could produce different baselines.

## Compatibility

| Requirement | Notes |
|---|---|
| arm64-v8a | Pre-built for arm64. Other ABIs: rebuild from source. |
| Android >= 10 | App Zygote (the detection surface) was added in Android 10. |
| Magisk >= 24 + Zygisk | Module requires Zygisk API v5. KitsuneMask also works. |

## License

Apache 2.0
