#!/bin/sh

# Copyright (C) 2022 Red Hat, Inc.
#
# Author: Daiki Ueno
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS. If not, see <https://www.gnu.org/licenses/>.

: ${builddir=.}

. "$srcdir/scripts/common.sh"

case "$HOST_OS" in
    FreeBSD)
	if ! sysctl -n kern.ipc.tls.enable | grep 1 > /dev/null; then
		exit 77
	fi

	kernel_version_check 13 0 || exit 77
	;;
    Linux)
	if ! grep '^tls ' /proc/modules 2>&1 /dev/null; then
		exit 77
	fi

	kernel_version_check 5 10 || exit 77
	;;
esac

testdir=`create_testdir ktls`

cfg="$testdir/config"

cat << EOF > "$cfg"
[global]
ktls = true
EOF

GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID=1 \
GNUTLS_SYSTEM_PRIORITY_FILE="$cfg" \
"$builddir/gnutls_ktls" "$@"
rc=$?

rm -rf "$testdir"
exit $rc
