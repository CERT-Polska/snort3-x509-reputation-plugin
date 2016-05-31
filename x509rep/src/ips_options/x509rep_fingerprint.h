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

//#include <iostream>
#include <vector>
#include <string>
#include <set>

#ifndef x509Rep_FINGERPRINT_CONTENER
#define x509Rep_FINGERPRINT_CONTENER

class FingerprintContener
{
public:
    FingerprintContener() {}
    virtual ~FingerprintContener(){}

    virtual int init(char* black_list_path, char* white_list_path, bool black_list_disable,bool white_list_disable, std::vector<std::string> black_list_vector, std::vector<std::string> white_list_vector)=0;
    virtual bool is_in_white_list(std::string fingerprint)=0;
    virtual bool is_in_black_list(std::string fingerprint)=0;
};

#endif
