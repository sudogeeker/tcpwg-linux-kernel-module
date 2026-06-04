# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

WIREGUARD_VERSION = 1.0.0
OMIT_ENDPOINTS ?=

KERNELRELEASE ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DEPMOD ?= depmod
DEPMODBASEDIR ?= /
DKMS ?= dkms
DKMS_NAME ?= tcp-wg
DKMS_VERSION ?= $(WIREGUARD_VERSION)
DKMSDIR ?= $(SRCDIR)/$(DKMS_NAME)-$(DKMS_VERSION)

PWD := $(shell pwd)

all: module
debug: module-debug

ifneq ($(V),1)
MAKEFLAGS += --no-print-directory
endif

module:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules

module-debug:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) V=1 CONFIG_TCP_WG_DEBUG=y WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

module-install:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules_install
	$(DEPMOD) -b "$(DEPMODBASEDIR)" -a $(KERNELRELEASE)

install: dkms-install

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
DKMS_SOURCES := version.h Makefile Kbuild Kconfig dkms.conf $(filter-out version.h %.mod.c tests/%,$(call rwildcard,,*.c *.h *.S *.pl *.include))
dkms-source-install: $(DKMS_SOURCES)
	@$(foreach f,$(DKMS_SOURCES),install -v -m0644 -D $(f) $(DESTDIR)$(DKMSDIR)/$(f);)
	@sed -i 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION="$(DKMS_VERSION)"/' "$(DESTDIR)$(DKMSDIR)/dkms.conf"

dkms-install: dkms-source-install
	@if [ -n "$(DESTDIR)" ]; then \
		echo "error: dkms-install cannot run with DESTDIR; use dkms-source-install for packaging" >&2; \
		exit 1; \
	fi
	@if ! command -v "$(DKMS)" >/dev/null 2>&1; then \
		echo "error: dkms is required for make install." >&2; \
		exit 1; \
	fi
	@if [ ! -d "/var/lib/dkms/$(DKMS_NAME)/$(DKMS_VERSION)" ]; then \
		"$(DKMS)" add -m "$(DKMS_NAME)" -v "$(DKMS_VERSION)"; \
	fi
	@if "$(DKMS)" status -m "$(DKMS_NAME)" -v "$(DKMS_VERSION)" -k "$(KERNELRELEASE)" 2>/dev/null | grep -Eq 'built|installed'; then \
		"$(DKMS)" remove -m "$(DKMS_NAME)" -v "$(DKMS_VERSION)" -k "$(KERNELRELEASE)" || true; \
	fi
	"$(DKMS)" build -m "$(DKMS_NAME)" -v "$(DKMS_VERSION)" -k "$(KERNELRELEASE)"
	"$(DKMS)" install -m "$(DKMS_NAME)" -v "$(DKMS_VERSION)" -k "$(KERNELRELEASE)" --force
	$(DEPMOD) -b "$(DEPMODBASEDIR)" -a $(KERNELRELEASE)

style:
	$(KERNELDIR)/scripts/checkpatch.pl -f --max-line-length=4000 --codespell --color=always $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h) $(wildcard selftest/*.c)

check: clean
	scan-build --html-title=wireguard-linux-compat -maxloop 100 --view --keep-going $(MAKE) module CONFIG_TCP_WG_DEBUG=y C=2 CF="-D__CHECK_ENDIAN__"

coccicheck: clean
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_TCP_WG_DEBUG=y coccicheck MODE=report

cloc:
	@cloc --skip-uniqueness --by-file --extract-with="$$(readlink -f ../kernel-tree-scripts/filter-compat-defines.sh) >FILE< > \$$(basename >FILE<)" $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h)

-include tests/debug.mk

.PHONY: all module module-debug apply-patches module-install install dkms-source-install dkms-install clean cloc check style
