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
#include <string.h>
#include <vector>
#include <fstream>

#include "log/messages.h"
#include "x509rep_conf.h"

using namespace std;


x509Rep_config::x509Rep_config()
{
    white_fingerprint_list.clear();
    black_fingerprint_list.clear();

    black_list_path=NULL;
    white_list_path=NULL;
    trusted_CA_path=NULL;
    untrusted_CA_path=NULL;
    save_cert_path=NULL;
    logfile=NULL;

    black_list_disable=0;
    white_list_disable=0;
    trusted_CA_disable=0;
    untrusted_CA_disable=0;
    full_chain_verify=0;
}

x509Rep_config::~x509Rep_config()
{
    free(black_list_path);
    free(white_list_path);
    free(trusted_CA_path);
    free(untrusted_CA_path);
    free(save_cert_path);
    free(logfile);
}

int x509Rep_config::set_black_list_path(char * black_list_path)
{
    this->black_list_path=black_list_path;
    return 1;
}

int x509Rep_config::set_white_list_path(char * white_list_path)
{
    this->white_list_path=white_list_path;
    return 1;
}

int x509Rep_config::set_trusted_CA_path(char * trusted_CA_path)
{
    this->trusted_CA_path=trusted_CA_path;
    return 1;
}

int x509Rep_config::set_untrusted_CA_path(char * untrusted_CA_path)
{
    this->untrusted_CA_path=untrusted_CA_path;
    return 1;
}

int x509Rep_config::set_black_list_disable(bool black_list_disable)
{
    this->black_list_disable=black_list_disable;
    return 1;
}

int x509Rep_config::set_white_list_disable(bool white_list_disable)
{
    this->white_list_disable=white_list_disable;
    return 1;
}

int x509Rep_config::set_trusted_CA_disable(bool trusted_CA_disable)
{
    this->trusted_CA_disable=trusted_CA_disable;
    return 1;
}

int x509Rep_config::set_untrusted_CA_disable(bool untrusted_CA_disable)
{
    this->untrusted_CA_disable=untrusted_CA_disable;
    return 1;
}

int x509Rep_config::set_full_chain_verify(bool full_chain_verify)
{
    this->full_chain_verify=full_chain_verify;
    return 1;
}

int x509Rep_config::add_black_fingerprint(string black_fingerprint)
{
    black_fingerprint_list.push_back(black_fingerprint);
    return 1;
}

int x509Rep_config::add_white_fingerprint(string white_fingerprint)
{
    white_fingerprint_list.push_back(white_fingerprint);
    return 1;
}

int x509Rep_config::set_logfile(char * logfile)
{
    this->logfile=logfile;
    return 1;
}

int x509Rep_config::set_save_cert_path(char * save_cert)
{
    this->save_cert_path=save_cert;
    return 1;
}

bool x509Rep_config::get_black_list_disable()
{
    return black_list_disable;
}

bool x509Rep_config::get_white_list_disable()
{
    return white_list_disable;
}

bool x509Rep_config::get_trusted_CA_disable()
{
    return trusted_CA_disable;
}

bool x509Rep_config::get_untrusted_CA_disable()
{
    return untrusted_CA_disable;
}

bool x509Rep_config::get_full_chain_verify()
{
    return full_chain_verify;
}

vector<string> x509Rep_config::get_black_fingerprint_list()
{
    return black_fingerprint_list;
}

vector<string> x509Rep_config::get_white_fingerprint_list()
{
    return white_fingerprint_list;
}

char* x509Rep_config::get_black_list_path()
{
    char* black_list_path_copy=NULL;

    if(black_list_path!=NULL)
    {
        black_list_path_copy = new char [strlen(black_list_path)+1];
        strcpy(black_list_path_copy, black_list_path);
    }

    return black_list_path_copy;
}

char* x509Rep_config::get_white_list_path()
{
    char* white_list_path_copy=NULL;

    if(white_list_path!=NULL)
    {
        white_list_path_copy = new char [strlen(white_list_path)+1];
        strcpy(white_list_path_copy, white_list_path);
    }

    return white_list_path_copy;
}

char* x509Rep_config::get_trusted_CA_path()
{
    char* trusted_CA_path_copy=NULL;

    if(trusted_CA_path!=NULL)
    {
        trusted_CA_path_copy = new char [strlen(trusted_CA_path)+1];
        strcpy(trusted_CA_path_copy, trusted_CA_path);
    }

    return trusted_CA_path_copy;
}

char* x509Rep_config::get_untrusted_CA_path()
{
    char* untrusted_CA_path_copy=NULL;

    if(untrusted_CA_path!=NULL)
    {
        untrusted_CA_path_copy = new char [strlen(untrusted_CA_path)+1];
        strcpy(untrusted_CA_path_copy, untrusted_CA_path);
    }

    return untrusted_CA_path_copy;
}

char* x509Rep_config::get_logfile()
{
    char* logfile_copy=NULL;

    if(logfile!=NULL)
    {
        logfile_copy = new char [strlen(logfile)+1];
        strcpy(logfile_copy, logfile);
    }

    return logfile_copy;
}

char* x509Rep_config::get_save_cert_path()
{
    char* save_cert_path_copy=NULL;

    if(save_cert_path!=NULL)
    {
        save_cert_path_copy = new char [strlen(save_cert_path)+1];
        strcpy(save_cert_path_copy, save_cert_path);
    }

    return save_cert_path_copy;
}

int x509Rep_config::clean_up()
{
    free(black_list_path);
    free(white_list_path);
    free(trusted_CA_path);
    free(untrusted_CA_path);
    free(save_cert_path);
    free(logfile);

    white_fingerprint_list.clear();
    black_fingerprint_list.clear();

    black_list_path=NULL;
    white_list_path=NULL;
    trusted_CA_path=NULL;
    untrusted_CA_path=NULL;
    save_cert_path=NULL;
    logfile=NULL;

    black_list_disable=0;
    white_list_disable=0;
    trusted_CA_disable=0;
    untrusted_CA_disable=0;
    full_chain_verify=0;

    return 1;
}

int x509Rep_config::auto_set()
{
    if(black_list_path==NULL and black_fingerprint_list.empty())
    {
        black_list_disable=1;
    }

    if(white_list_path==NULL and white_fingerprint_list.empty())
    {
        white_list_disable=1;
    }

    if(trusted_CA_path==NULL)
    {
        trusted_CA_disable=1;
    }

    if(untrusted_CA_path==NULL)
    {
        untrusted_CA_disable=1;
    }

    return 1;
}

int x509Rep_config::check_session_config()
{
    if( black_list_disable and white_list_disable and trusted_CA_disable and untrusted_CA_disable)
    {
        FatalError("There is no active checklist. All lists (BlackList, WhiteList, TrustedCA, UntrustedCA) are disable \n");
    }

    if(save_cert_path!=NULL)
    {
        fstream file;
        file.open(save_cert_path, ios::out);
        if(!file)
        {
            FatalError("Can't open file %s \n", save_cert_path);
        }
        file.close();
    }

    return 1;
}
