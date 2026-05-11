#!/sbin/sh
# DirtySepolicy Bypass — Magisk module installer

SKIPUNZIP=0

# Require Magisk >= 24.0 (first version with stable Zygisk API v5).
if [ "$MAGISK_VER_CODE" -lt 24000 ]; then
  ui_print "! Magisk 24.0+ required (you have $MAGISK_VER)"
  abort  "! Aborting"
fi

# Require Zygisk to be enabled. Magisk exports ZYGISK_ENABLED only in 24+.
if [ "$ZYGISK_ENABLED" != "true" ] && [ "$ZYGISK_ENABLED" != "1" ]; then
  # Older Magisk doesn't export it; check the setting directly.
  if [ -f /data/adb/magisk.db ]; then
    z=$(magisk --sqlite "SELECT value FROM settings WHERE key='zygisk'" 2>/dev/null | sed 's/.*=//')
    if [ "$z" != "1" ]; then
      ui_print "! Zygisk is not enabled."
      ui_print "! Enable it in Magisk -> Settings -> Zygisk, then reflash."
      abort  "! Aborting"
    fi
  fi
fi

ui_print "- Installing DirtySepolicy Bypass v1.0.0"
ui_print "- ABI: $ARCH ($IS64BIT-bit)"

# Magisk auto-extracts $ZIPFILE into $MODPATH. Confirm the zygisk payload
# for this ABI is present.
case "$ARCH" in
  arm64)   ABI_LIB=arm64-v8a   ;;
  arm)     ABI_LIB=armeabi-v7a ;;
  x64)     ABI_LIB=x86_64      ;;
  x86)     ABI_LIB=x86         ;;
  *)       abort "! Unsupported ABI: $ARCH" ;;
esac

if [ ! -f "$MODPATH/zygisk/$ABI_LIB.so" ]; then
  ui_print "! Missing zygisk/$ABI_LIB.so in module zip"
  abort  "! Aborting"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644

ui_print "- Reboot to activate."
