# Sample OpenSSL 3.x Provider — Makefile
#
# Targets:
#   all           build sample.so + test_provider
#   test          build and run tests (OPENSSL_MODULES set automatically)
#   clean         remove build artifacts
#   install       copy sample.so to $(MODULESDIR)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic
CFLAGS  += -std=c11

# OpenSSL headers / libraries
OPENSSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null || echo "-I/usr/include")
OPENSSL_LDFLAGS := $(shell pkg-config --libs   openssl 2>/dev/null || echo "-lssl -lcrypto")

# Default install path for provider modules (matches openssl-3 Debian/Ubuntu)
MODULESDIR ?= $(shell openssl version -m 2>/dev/null | \
              sed -n 's/.*MODULESDIR: "\(.*\)".*/\1/p')

# ── Build directories ──────────────────────────────────────────────────────

BUILDDIR := build
OBJDIR   := $(BUILDDIR)/obj

# ── Provider shared library ────────────────────────────────────────────────

PROV_SRCS := src/entry.c       \
             src/digest.c      \
             src/cipher.c      \
             src/mac.c         \
             src/kdf.c         \
             src/rand.c        \
             src/keymgmt_rsa.c \
             src/keymgmt_ec.c  \
             src/signature.c   \
             src/asymcipher.c  \
             src/keyexch.c

PROV_OBJS := $(PROV_SRCS:src/%.c=$(OBJDIR)/%.o)
PROV_SO   := $(BUILDDIR)/sample.so

PROV_CFLAGS := $(CFLAGS) $(OPENSSL_CFLAGS) -Iinclude \
               -fPIC -fvisibility=hidden -D_GNU_SOURCE

# ── Test binary ────────────────────────────────────────────────────────────

TEST_SRC  := test/test.c
TEST_BIN  := $(BUILDDIR)/test_provider
TEST_CFLAGS := $(CFLAGS) $(OPENSSL_CFLAGS) -Iinclude

# ── Rules ──────────────────────────────────────────────────────────────────

.PHONY: all test clean install

all: $(PROV_SO) $(TEST_BIN)

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(PROV_CFLAGS) -c $< -o $@

$(PROV_SO): $(PROV_OBJS)
	$(CC) -shared -Wl,-soname,sample.so \
	      -o $@ $^ $(OPENSSL_LDFLAGS) -lpthread

$(TEST_BIN): $(TEST_SRC) | $(BUILDDIR)
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(OPENSSL_LDFLAGS)

$(OBJDIR):
	mkdir -p $@

$(BUILDDIR):
	mkdir -p $@

# ── Test ───────────────────────────────────────────────────────────────────

test: all
	@echo "--- Running tests (OPENSSL_MODULES=$(BUILDDIR)) ---"
	OPENSSL_MODULES=$(BUILDDIR) $(TEST_BIN)

# ── Clean ──────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILDDIR)

# ── Install ────────────────────────────────────────────────────────────────

install: $(PROV_SO)
ifeq ($(MODULESDIR),)
	$(error Cannot determine MODULESDIR. Set it explicitly: make install MODULESDIR=/path/to/ossl-modules)
endif
	install -Dm755 $(PROV_SO) $(MODULESDIR)/sample.so
	@echo "Installed to $(MODULESDIR)/sample.so"
