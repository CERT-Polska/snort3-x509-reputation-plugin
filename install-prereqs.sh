#!/bin/bash

if [ "$(id -u)" != "0" ] ; then
    echo "This script must be run as root" 2>&1
    exit 1
fi

apt-get update
apt-get install -y gcc g++ build-essential autoconf libtool pkg-config libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev libluajit-5.1-dev luajit source-highlight libhwloc-dev wget libssl-dev

wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xzf daq-2.0.6.tar.gz
cd daq-2.0.6
autoreconf -vfi
./configure || exit 1
make || exit 1
make install
ldconfig
cd ..
rm -rf daq-2.0.6.tar.gz daq-2.0.6/
