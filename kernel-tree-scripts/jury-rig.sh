#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

K="$1"
WG="$(readlink -f "$(dirname "$(readlink -f "$0")")/../src/")"

if [[ ! -e $K/net/Kconfig ]]; then
	echo "You must specify the location of kernel sources as the first argument." >&2
	exit 1
fi

ln -sfT "$WG" "$K/net/tcp-wg"
sed -i "/^obj-\\\$(CONFIG_NETFILTER).*+=/a obj-\$(CONFIG_TCP_WG) += tcp-wg/" "$K/net/Makefile"
sed -i "/^if INET\$/a source \"net/tcp-wg/Kconfig\"" "$K/net/Kconfig"
