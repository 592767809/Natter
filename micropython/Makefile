include deps.mk

PROG := natter
BUILD_DIR := $(CURDIR)/build
PATCH_DIR := $(CURDIR)/patch
COMP_DIR := $(BUILD_DIR)/compressed
MP_TAR := $(BUILD_DIR)/$(MICROPYTHON_TARNAME)
MP_SRC := $(BUILD_DIR)/$(MICROPYTHON_DIRNAME)
MP_PACTHED := $(MP_SRC)/.patched
LXP_TAR := $(BUILD_DIR)/$(LXPACK_TARNAME)
LXP_SRC := $(BUILD_DIR)/$(LXPACK_DIRNAME)
PROG_BIN := $(BUILD_DIR)/$(PROG)
COMP_BIN := $(COMP_DIR)/$(PROG)

MP_MAKE_EXTRA := \
	MICROPY_STANDALONE=1 \
	MICROPY_PY_BTREE=0 \
	MICROPY_PY_FFI=0 \
	MICROPY_PY_SSL=0 \
	MICROPY_PY_TERMIOS=0 \
	MICROPY_SSL_MBEDTLS=0 \
	MICROPY_USE_READLINE=0 \
	MICROPY_VFS_FAT=0 \
	MICROPY_VFS_LFS1=0 \
	MICROPY_VFS_LFS2=0 \
	MICROPY_GIT_TAG='v$(MICROPYTHON_VERSION)-natter' \
	MICROPY_GIT_HASH='<no hash>' \
	SOURCE_DATE_EPOCH=0 \
	HELP_BUILD_ERROR=

ifdef CROSS_COMPILE
	MP_MAKE_EXTRA := $(MP_MAKE_EXTRA) CROSS_COMPILE='$(CROSS_COMPILE)'
endif
ifdef DEBUG
	MP_MAKE_EXTRA := $(MP_MAKE_EXTRA) DEBUG='$(DEBUG)'
endif
ifdef V
	MP_MAKE_EXTRA := $(MP_MAKE_EXTRA) V='$(V)'
endif

MP_CFLAGS_EXTRA := \
	-frandom-seed=natter \
	-Wdate-time \
	-Wno-error=clobbered \
	-DMICROPY_PY_SYS_TRACEBACKLIMIT=1 \
	-DMICROPY_PY_RE_MATCH_GROUPS=1 \
	-DMICROPY_PY_RE_MATCH_SPAN_START_END=1 \
	-DMICROPY_NLR_SETJMP=1

ifeq ($(findstring m68k,$(shell $(CROSS_COMPILE)gcc -dumpmachine)),m68k)
	MP_CFLAGS_EXTRA := $(MP_CFLAGS_EXTRA) -malign-int
endif

ifeq ($(STATIC),1)
MP_LDFLAGS_EXTRA := -static
endif

all: $(PROG_BIN)

download: $(MP_TAR) $(LXP_TAR)

compress: $(COMP_BIN)

clean:
	$(RM) -r '$(MP_SRC)' '$(LXP_SRC)' '$(COMP_DIR)' '$(PROG_BIN)'

distclean:
	$(RM) -r '$(BUILD_DIR)'

$(MP_TAR):
	mkdir -p '$(BUILD_DIR)'
	curl -Lfo '$@' '$(MICROPYTHON_SRCURL)'
	echo '$(MICROPYTHON_SHA256) *$@' | sha256sum -c -

$(LXP_TAR):
	mkdir -p '$(BUILD_DIR)'
	curl -Lfo '$@' '$(LXPACK_SRCURL)'
	echo '$(LXPACK_SHA256) *$@' | sha256sum -c -

untar: $(MP_TAR) $(LXP_TAR)
	rm -rf '$(MP_SRC)' '$(LXP_SRC)'
	cd '$(BUILD_DIR)' && tar xJf '$(MP_TAR)'
	cd '$(BUILD_DIR)' && tar xJf '$(LXP_TAR)'

$(MP_PACTHED): $(wildcard $(PATCH_DIR)/*.patch)
	test -d '$(MP_SRC)' || $(MAKE) untar
	find '$(MP_SRC)' -type f -name '*.orig' -exec sh -c 'mv "$$1" "$${1%.orig}"' _ {} \;
	for p in '$(PATCH_DIR)'/*.patch; do \
		cd '$(MP_SRC)' && patch -bp1 < "$$p"; \
	done
	touch '$@'

patch: $(MP_PACTHED)

mpy_cross: $(MP_PACTHED)
	$(MAKE) -C '$(MP_SRC)/mpy-cross' \
		PROG=mpy-cross \
		CROSS_COMPILE= \
		CFLAGS_EXTRA= \
		LDFLAGS_EXTRA=

$(PROG_BIN): mpy_cross
	$(MAKE) -C '$(MP_SRC)/ports/unix' install \
		VARIANT=standard \
		BINDIR='$(BUILD_DIR)' \
		PROG='$(PROG)' \
        FROZEN_MANIFEST='$(CURDIR)/pymodule/_manifest.py' \
        USER_C_MODULES='$(CURDIR)/cmodule' \
        CFLAGS_EXTRA='$(MP_CFLAGS_EXTRA)' \
        LDFLAGS_EXTRA='$(MP_LDFLAGS_EXTRA)' \
        $(MP_MAKE_EXTRA)

$(COMP_BIN): $(PROG_BIN)
	test -d '$(LXP_SRC)' || $(MAKE) untar
	$(MAKE) -C '$(LXP_SRC)' install \
		BINDIR='$(COMP_DIR)' \
		PAYLOAD='$(PROG_BIN)'

.PHONY: all download untar patch mpy_cross compress clean
