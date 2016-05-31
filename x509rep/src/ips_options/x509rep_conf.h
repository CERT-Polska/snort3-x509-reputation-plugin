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

#include <set> //////////////
#include <string>

#ifndef x509Rep_CONFIG_H
#define x509Rep_CONFIG_H

const int TRUSTED_CA_PATH=0;
const int UNTRUSTED_CA_PATH=1;

using namespace std;

class x509Rep_config
{
private:
    char * black_list_path;
    char * white_list_path;
    char * trusted_CA_path;
    char * untrusted_CA_path;
    char * save_cert_path;
    char * logfile;

    bool black_list_disable;
    bool white_list_disable;
    bool trusted_CA_disable;
    bool untrusted_CA_disable;
    bool full_chain_verify;

    vector<string> white_fingerprint_list;
    vector<string> black_fingerprint_list;

public:
    x509Rep_config();
    ~x509Rep_config();

    int set_black_list_path(char * black_list_path);
    int set_white_list_path(char * white_list_path);
    int set_trusted_CA_path(char * trusted_CA_path);
    int set_untrusted_CA_path(char * untrusted_CA_path);
    int set_save_cert_path(char * save_cert);

    int set_black_list_disable(bool black_list_disable);
    int set_white_list_disable(bool white_list_disable);
    int set_trusted_CA_disable(bool trusted_CA_disabl);
    int set_untrusted_CA_disable(bool untrusted_CA_disable);
    int set_full_chain_verify(bool full_chain_verify);

    int add_black_fingerprint(string black_fingerprint);
    int add_white_fingerprint(string white_fingerprint);
    int set_logfile(char * logfile);
    int auto_set();
    int check_session_config();

    bool get_black_list_disable();
    bool get_white_list_disable();
    bool get_trusted_CA_disable();
    bool get_untrusted_CA_disable();
    bool get_full_chain_verify();

    char* get_logfile();

    vector<string> get_black_fingerprint_list();
    vector<string> get_white_fingerprint_list();

    char* get_black_list_path();
    char* get_white_list_path();
    char* get_trusted_CA_path();
    char* get_untrusted_CA_path();
    char* get_save_cert_path();

    int clean_up();
};

#endif
