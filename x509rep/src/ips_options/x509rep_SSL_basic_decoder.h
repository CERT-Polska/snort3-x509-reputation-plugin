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

#include <vector>
#include <string>
#include "x509rep_SSL_decoder.h"

#ifndef x509Rep_PARSER_STATE_H
#define x509Rep_PARSER_STATE_H

class SSLBasicDecoder: public SSLDecoder
{
public:
    SSLBasicDecoder();
    ~SSLBasicDecoder();

    int init(Packet* p);
    int is_certificate();
    std::vector<std::string> get_certificate_vector();

private:
    Packet* p;
    std::string all_certificates;
    std::vector<std::string> cert_buffer;
    int all_data;

    int decode_cert_string(std::string all_certificates);
    void get_data();
    int check_data();
    void save(std::string data);
};

#endif

