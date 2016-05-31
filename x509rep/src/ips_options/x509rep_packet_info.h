//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// ips_x509Rep.cc author CERT Polska <info@cert.pl>

#include <string>
#include "util_net.h"

#ifndef SRCX_PACKET_INFO
#define SRCX_PACKET_INFO

class Packet_info
{
public:
    Packet_info() {}
    ~Packet_info() {}
    int set_src_ip_addr(const sfip_t* ip);
    int set_dst_ip_addr(const sfip_t* ip);
    int set_time_info(timeval tv);
    const char* get_src_ip_addr();
    const char* get_dst_ip_addr();
    const char* get_time_info();
    const char* get_hour();

private:
    std::string src_ip_addr;
    std::string dst_ip_addr;
    std::string time_info;
    std::string hour;
};

#endif

