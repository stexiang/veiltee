# VeilTEE —— NDK 交叉编译
#
# 用法:
#   make NDK=$HOME/Library/Android/sdk/ndk/android-ndk-r26d
#   make host          # 本机自检
#   make clean

NDK ?= $(HOME)/Library/Android/sdk/ndk/android-ndk-r26d
HOST := $(shell uname -s | tr 'A-Z' 'a-z')
TC   := $(NDK)/toolchains/llvm/prebuilt/$(HOST)-x86_64
API  ?= 29

CC_A64 := $(TC)/bin/aarch64-linux-android$(API)-clang
CC_X64 := $(TC)/bin/x86_64-linux-android$(API)-clang

CFLAGS  := -O2 -std=c11 -Wall -Wextra -fPIC -DANDROID
LDLIBS  := -llog -ldl
OUT     := ../bin

CORE    := p256.c sha256.c attest.c veil_cfg.c
PAYLOAD := payload.c rewrite.c plthook.c $(CORE)
HARDEN  := hardening.c fingerprint.c plthook.c veil_cfg.c
DAEMON  := veild

.PHONY: all a64 x64 host clean

all: a64 x64

a64:
	@mkdir -p $(OUT)/arm64-v8a
	$(CC_A64) $(CFLAGS) -shared -o $(OUT)/arm64-v8a/libveil.so $(PAYLOAD) $(LDLIBS)
	$(CC_A64) $(CFLAGS) -shared -o $(OUT)/arm64-v8a/libveil_app.so $(HARDEN) $(LDLIBS)
	$(CC_A64) $(CFLAGS) -o $(OUT)/arm64-v8a/veilteed veilteed.c injector.c veil_cfg.c $(LDLIBS)
	$(CC_A64) $(CFLAGS) -o $(OUT)/arm64-v8a/veilctl veilctl.c keybox_check.c $(CORE) $(LDLIBS)
	@echo "arm64-v8a done"

x64:
	@mkdir -p $(OUT)/x86_64
	$(CC_X64) $(CFLAGS) -shared -o $(OUT)/x86_64/libveil.so $(PAYLOAD) $(LDLIBS)
	$(CC_X64) $(CFLAGS) -shared -o $(OUT)/x86_64/libveil_app.so $(HARDEN) $(LDLIBS)
	$(CC_X64) $(CFLAGS) -o $(OUT)/x86_64/veilteed veilteed.c injector.c veil_cfg.c $(LDLIBS)
	$(CC_X64) $(CFLAGS) -o $(OUT)/x86_64/veilctl veilctl.c keybox_check.c $(CORE) $(LDLIBS)
	@echo "x86_64 done"

host:
	clang -O2 -std=c11 -Wall -o /tmp/veil_selftest selftest.c $(CORE)
	/tmp/veil_selftest

clean:
	rm -rf $(OUT)/arm64-v8a $(OUT)/x86_64
