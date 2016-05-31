#!/bin/bash

if [ "$(id -u)" != "0" ] ; then
    echo "This script must be run as root" 2>&1
    exit 1
fi

top_dir=`pwd`
snort_path="/opt/snort"

cd "${top_dir}/x509rep"
export PKG_CONFIG_PATH="$snort_path/lib/pkgconfig"
autoreconf -vfi
./configure --prefix="$snort_path" --with-snort-includes="$snort_path/include/snort" || exit 1
make || exit 1
make install
