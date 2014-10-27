SHELL = /bin/bash

UNAME = $(shell uname -s)
#PLATFORM = host_32
#PLATFORM = host_64
#PLATFORM = arm_droid
ifeq ($(PLATFORM),arm_droid)
#ARCH=x86
SYSROOT=/opt/ndk/platforms/android-14/arch-arm
TOOLCHAIN=/opt/ndk/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86
PREFIX = $(TOOLCHAIN)/bin/arm-linux-androideabi-
endif

CC = $(PREFIX)gcc
LD = $(PREFIX)ld

ifneq ($(ARCH),)
ARCH_FLAGS = ARCH=$(ARCH)
endif

ifneq ($(SYSROOT),)
SYSROOT_FLAGS = --sysroot=$(SYSROOT)
endif

CFLAGS = $(PFX_FLAGS) $(SYSROOT_FLAGS)
CFLAGS += -W -Wall -Werror
CFLAGS += -g -MP -pipe -O2
CFLAGS += -fno-reorder-blocks -fno-strict-aliasing -pthread
CFLAGS += -std=gnu99 -fgnu89-inline -rdynamic
CFLAGS += -D_GNU_SOURCE
ifeq ($(PLATFORM),host_32)
CFLAGS += -m32
endif
ifeq ($(PLATFORM),host_64)
CFLAGS += -m64
endif

LDFLAGS =
SO_LDFLAGS = -shared -L.
SO_LDFLAGS += -pthread -Xlinker --start-group
SO_LDFLAGS_POST = -Xlinker --end-group
CC_SO_LDFLAGS = $(PFX_FLAGS) $(SYSROOT_FLAGS)
ifeq ($(PLATFORM),host_32)
CC_SO_LDFLAGS += -m32
endif
ifeq ($(PLATFORM),host_64)
CC_SO_LDFLAGS += -m64
endif
CC_SO_LDFLAGS += -nostartfiles $(SO_LDFLAGS)

BIN_LDFLAGS = $(PFX_FLAGS) $(SYSROOT_FLAGS)
BIN_LDFLAGS += -Bdynamic -rdynamic
ifeq ($(PLATFORM),host_32)
BIN_LDFLAGS += -m32
endif
ifeq ($(PLATFORM),host_64)
BIN_LDFLAGS += -m64
endif
ifneq ($(SYSROOT),)
BIN_LDFLAGS += -L$(SYSROOT)/usr/lib -Wl,-rpath-link,$(SYSROOT)/usr/lib
endif
BIN_LDFLAGS += -L. -Wl,-rpath,. #-Wl,--verbose
BIN_LDFLAGS += -pthread -Xlinker --start-group
ifeq ($(PLATFORM),host_64)
BIN_LDFLAGS += $(SYSROOT)/usr/lib64/libdl.so
else
BIN_LDFLAGS += $(SYSROOT)/usr/lib/libdl.so
endif
BIN_LDFLAGS_POST = -Xlinker --end-group -lc

SO_OBJS = \
	libelf_hook.so \
	libtest1.so \
	libtest2.so \
	libhooks.so

BINS = \
	test \
	eh_test


.PHONY: all clean check_env

all: check_env $(SO_OBJS) $(BINS)

check_env:
	@if test "$(PLATFORM)" != "host_32" && test "$(PLATFORM)" != "host_64"; then \
		echo -e "PLATFORM not set correctly, must be one of the following:"; \
		echo -e "\t{ host_32, host_64 }\n"; \
		exit 1; \
	fi

ifneq ($(PLATFORM),host_64)
libtest1.lo: libtest1.c
	$(ARCH_FLAGS) $(CC) $(CFLAGS) -c -MMD -MT $@ -MF "$(patsubst %.lo,%.ld,$@)" $< -o $@
endif

libelf_hook.so: elf_hook.lo elf_hook_wrap.lo
	$(ARCH_FLAGS) $(CC) $(CC_SO_LDFLAGS) $^ $(SO_LDFLAGS_POST) -Wl,-soname,$@ -o $@

libtest1.so: libtest1.lo
	$(ARCH_FLAGS) $(CC) $(CC_SO_LDFLAGS) $^ $(SO_LDFLAGS_POST) -Wl,-soname,$@ -o $@

libtest2.so: libtest2.lo
	$(ARCH_FLAGS) $(CC) $(CC_SO_LDFLAGS) $^ $(SO_LDFLAGS_POST) -Wl,-soname,$@ -o $@

test: libtest1.so libtest2.so libelf_hook.so test.o
	$(ARCH_FLAGS) $(CC) $(BIN_LDFLAGS) $^ $(BIN_LDFLAGS_POST) -o $@

eh_test: libtest1.so libtest2.so libelf_hook.so eh_test.o
	$(ARCH_FLAGS) $(CC) $(BIN_LDFLAGS) $^ $(BIN_LDFLAGS_POST) -o $@

libhooks.so: hooks.lo
	$(ARCH_FLAGS) $(CC) $(CC_SO_LDFLAGS) $^ $(SO_LDFLAGS_POST) -Wl,-soname,$@ -o $@


.SUFFIXES: .c .cpp .o .lo

.c.lo:
	$(ARCH_FLAGS) $(CC) $(CFLAGS) -fPIC -DPIC -c -MMD -MT $@ -MF "$(patsubst %.lo,%.ld,$@)" $< -o $@

.c.o:
	$(ARCH_FLAGS) $(CC) $(CFLAGS) -fPIC -DPIC -c -MMD -MT $@ -MF "$(patsubst %.o,%.d,$@)" $< -o $@

clean:
	$(RM) $(SO_OBJS) *.so* *.dylib
	$(RM) *.lo *.ld *.o *.d
	$(RM) $(BINS)

