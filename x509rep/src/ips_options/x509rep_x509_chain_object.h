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

#ifndef x509Rep_CHAIN_OBJECT
#define x509Rep_CHAIN_OBJECT

static const int FIRST_CERTIFICATE=0;
static const int SECOND_CERTIFICATE=1;
static const int THIRD_CERTIFICATE=2;
static const int FOURTH_CERTIFICATE=3;


class X509ChainObject
{
public:
    X509ChainObject() {}
    virtual ~X509ChainObject(){}

    virtual int init(char* trusted_CA_path, char* untrusted_CA_path, bool trusted_CA_disable, bool untrusted_CA_disable, bool full_check)=0;
    virtual int set_chain(std::vector<std::string> cert_buffer)=0;
    virtual int get_number_of_certificates()=0;
    virtual char* get_cert_fingerprint(int cert_number)=0;
    virtual bool is_in_trusted_CA()=0;
    virtual bool is_in_untrusted_CA()=0;
    virtual char* get_subject_DN(int cert_number)=0;
    virtual char* get_issuer_DN(int cert_number)=0;
    virtual int save_certificates(std::string path)=0;
};

#endif
