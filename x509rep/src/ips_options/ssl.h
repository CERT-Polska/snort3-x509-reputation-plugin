
//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// ssl.h author Adam Keeton
// modified by CERT Polska <info@cert.pl>

#include "protocols/ssl.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <string>

#include "protocols/packet.h"

#define THREE_BYTE_LEN(x) (x[2] | x[1] << 8 | x[0] << 16)

#define SSL_ERROR_FLAGS \
    (SSL_BOGUS_HS_DIR_FLAG | \
    SSL_BAD_VER_FLAG | \
    SSL_BAD_TYPE_FLAG | \
    SSL_UNKNOWN_FLAG)

#define SSL3_FIRST_BYTE 0x16
#define SSL3_SECOND_BYTE 0x03
#define SSL2_CHELLO_BYTE 0x01
#define SSL2_SHELLO_BYTE 0x04

using namespace std;

uint32_t SSL_decode_with_cert(const uint8_t* pkt, int size, uint32_t pkt_flags, uint32_t prev_flags,uint8_t* alert_flags, uint16_t* partial_rec_len, int max_hb_len, string &all_certificates, int &all_data);
static uint32_t SSL_decode_v2(const uint8_t* pkt, int size, uint32_t pkt_flags);
static inline bool SSL_v3_back_compat_v2(SSLv2_chello_t* chello);
static uint32_t SSL_decode_v3(const uint8_t* pkt, int size, uint32_t pkt_flags, uint8_t* alert_flags, uint16_t* partial_rec_len, int max_hb_len, string &all_certificates, int &all_data);
static uint32_t SSL_decode_handshake_v3(const uint8_t* pkt, int size, uint32_t cur_flags, uint32_t pkt_flags, string &all_certificates, int &all_data);
static uint32_t SSL_decode_version_v3(uint8_t major, uint8_t minor);
