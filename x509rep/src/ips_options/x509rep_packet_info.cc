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

#include "x509rep_packet_info.h"
#include "util_net.h"

using namespace std;

int Packet_info::set_src_ip_addr(const sfip_t* ip)
{
    src_ip_addr=inet_ntoax(ip);
    return 1;
}

int Packet_info::set_dst_ip_addr(const sfip_t* ip)
{
    dst_ip_addr=inet_ntoax(ip);
    return 1;
}

int Packet_info::set_time_info(timeval tv)
{
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64];

    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);

    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%06d", tmbuf, tv.tv_usec);

    time_info=buf;
    hour=time_info.substr(11);
    return 1;
}

const char* Packet_info::get_src_ip_addr()
{
    return src_ip_addr.c_str();
}

const char* Packet_info::get_dst_ip_addr()
{
    return dst_ip_addr.c_str();
}

const char* Packet_info::get_time_info()
{
    return time_info.c_str();
}

const char* Packet_info::get_hour()
{
    return hour.c_str();
}
