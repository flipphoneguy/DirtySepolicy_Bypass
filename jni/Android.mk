LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE          := dirtysepbypass
LOCAL_SRC_FILES       := module.cpp
LOCAL_CFLAGS          := -Wall -Wextra -Werror -fvisibility=hidden -fvisibility-inlines-hidden
LOCAL_CPPFLAGS        := -std=c++17 -fno-exceptions -fno-rtti
LOCAL_LDFLAGS         := -Wl,--hash-style=both
LOCAL_LDLIBS          := -llog
LOCAL_STATIC_LIBRARIES :=
include $(BUILD_SHARED_LIBRARY)
