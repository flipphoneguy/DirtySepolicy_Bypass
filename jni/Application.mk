APP_ABI       := arm64-v8a armeabi-v7a x86 x86_64
APP_PLATFORM  := android-23
APP_STL       := c++_static
APP_CPPFLAGS  := -std=c++17 -fno-exceptions -fno-rtti
APP_CFLAGS    := -O2 -fdata-sections -ffunction-sections
APP_LDFLAGS   := -Wl,--gc-sections -Wl,--strip-all
