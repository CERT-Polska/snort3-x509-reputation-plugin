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
#include <openssl/x509.h>
#include "x509rep_x509_chain_object.h"

#ifndef x509Rep_BASIC_CHAIN_OBJECT
#define x509Rep_BASIC_CHAIN_OBJECT


class X509RepBasicChainObject : public X509ChainObject
{
public:
    X509RepBasicChainObject();
    ~X509RepBasicChainObject();

    int init(char* trusted_CA_path, char* untrusted_CA_path, bool trusted_CA_disable, bool untrusted_CA_disable, bool full_check);
    int set_chain(std::vector<std::string> cert_buffer);

    int get_number_of_certificates();
    char* get_cert_fingerprint(int cert_number);
    char* get_subject_DN(int cert_number);
	char* get_issuer_DN(int cert_number);

    bool is_in_trusted_CA();
    bool is_in_untrusted_CA();
	int save_certificates(std::string path);

private:
    char * trusted_CA_path;
    char * untrusted_CA_path;
    bool trusted_CA_disable;
    bool untrusted_CA_disable;
    bool full_check;

    X509_STORE* trusted_CA_store;
    X509_STORE* untrusted_CA_store;
    std::vector<X509*> cert_objects;

    X509_STORE* set_X509_STORE(std::string path);
    bool is_in_CA(X509 *cert, X509_STORE* store);
    int set_Trusted_X509_STORE();
    int set_Untrusted_X509_STORE();
    bool full_CA_verify(std::string path);
    bool is_self_signed(X509* cert);
};

#endif // x509Rep_X509_CHAIN_OBJECT




