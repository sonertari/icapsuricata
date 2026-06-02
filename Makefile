# Makefile — srv_suricata.so  (c-icap + libsuricata)
#
# Prerequisites
# ─────────────
#   1. c-icap development headers installed (e.g. libicapapi-dev or built from
#      source).  Adjust CICAP_PREFIX if installed in a non-standard location.
#
#   2. Suricata built and installed as a library:
#        ./configure --enable-shared ...
#        make && sudo make install
#        sudo make install-library install-headers
#      After that, `libsuricata-config` must be on your PATH.
#
# Usage
# ─────
#   make            — build srv_suricata.so
#   make clean      — remove build artefacts
#   make install    — copy .so to the c-icap modules directory

# ── Tool overrides ───────────────────────────────────────────────────────────
CC      ?= gcc
INSTALL ?= install

# ── c-icap settings ──────────────────────────────────────────────────────────
# Use c-icap's pkg-config if available; otherwise fall back to manual paths.
CICAP_PREFIX   ?= /usr

# Capture any hidden compiler macros required by the libraries, but should work without it too
CICAP_CFLAGS   := $(shell pkg-config --cflags c_icap 2>/dev/null || \
                   echo -I$(CICAP_PREFIX)/include/c-icap)

# srv_suricata.so runs inside c-icap, so we don't need to link against the full c-icap library
# CICAP_LDFLAGS  := $(shell pkg-config --libs   c_icap 2>/dev/null || \
#                   echo -L$(CICAP_PREFIX)/lib/c-icap)

# ── libsuricata settings ──────────────────────────────────────────────────────
SURI_CFLAGS    := $(shell libsuricata-config --cflags 2>/dev/null)

# Link explicitly against libsuricata
SURI_LDFLAGS   := $(shell libsuricata-config --libs)

# ── Compiler flags ───────────────────────────────────────────────────────────
CFLAGS  := -O2 -g -Wall -Wextra -Wno-unused-parameter \
           -fPIC \
           $(CICAP_CFLAGS) \
           $(SURI_CFLAGS)

LDFLAGS := -shared \
           $(CICAP_LDFLAGS) \
           $(SURI_LDFLAGS) \
           -lpthread

# ── Targets ──────────────────────────────────────────────────────────────────
TARGET  := srv_suricata.so
SRC     := srv_suricata.c dual_ring_buf.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built $@"

clean:
	rm -f $(TARGET)

# Destination for `make install` — override on the command line if needed.
MODULES_DIR ?= /usr/lib/c-icap

install: $(TARGET)
	$(INSTALL) -D -m 0755 $(TARGET) $(MODULES_DIR)/$(TARGET)
	@echo "Installed $(TARGET) → $(MODULES_DIR)/$(TARGET)"
