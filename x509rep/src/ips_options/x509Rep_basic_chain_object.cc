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


#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>

#include <vector>
#include <string>
#include <sstream>


#include "log/messages.h"

#include "x509Rep_basic_chain_object.h"

using namespace std;

X509RepBasicChainObject::X509RepBasicChainObject()
{
}

X509RepBasicChainObject::~X509RepBasicChainObject()
{
    int vector_size = cert_objects.size();

    if(trusted_CA_path!=NULL and !trusted_CA_disable)
    {
        X509_STORE_free(trusted_CA_store);
    }

    if(untrusted_CA_path!=NULL and !untrusted_CA_disable)
    {
        X509_STORE_free(untrusted_CA_store);
    }

    for(int i=0; i<vector_size; i++)
    {
        X509_free(cert_objects[i]);
    }

    delete [] trusted_CA_path;
    delete [] untrusted_CA_path;
}

int X509RepBasicChainObject::init(char* trusted_CA_path, char* untrusted_CA_path, bool trusted_CA_disable, bool untrusted_CA_disable,  bool full_check)
{
    this->trusted_CA_path=trusted_CA_path;
    this->untrusted_CA_path=untrusted_CA_path;
    this->trusted_CA_disable=trusted_CA_disable;
    this->untrusted_CA_disable=untrusted_CA_disable;
    this->full_check=full_check;

    if( !trusted_CA_disable and trusted_CA_path!=NULL)
    {
        set_Trusted_X509_STORE();
    }
    if( !untrusted_CA_disable and untrusted_CA_path!=NULL)
    {
        set_Untrusted_X509_STORE();
    }
}

int X509RepBasicChainObject::set_chain(vector<string> cert_buffer)
{
    int vector_size = cert_buffer.size();
    int single_cert_len;

    cert_objects.clear();
    OpenSSL_add_all_algorithms();

    for(int i=0; i<vector_size; i++)
    {
        X509* cert = X509_new();

        const unsigned char* test = reinterpret_cast<const unsigned char*>(cert_buffer[i].c_str());
        single_cert_len = cert_buffer[i].size();
        cert = d2i_X509 (NULL, &test, single_cert_len);

        if(cert!=NULL)
        {
            cert_objects.push_back(cert);
        }
    }
}

int X509RepBasicChainObject::get_number_of_certificates()
{
    return cert_objects.size();
}


char* X509RepBasicChainObject::get_cert_fingerprint(int cert_number)
{
    if(cert_objects.size()<=cert_number)
        return NULL;

    const int SHA1_LEN=20;

    char* single_fingerprint = new char [SHA1_LEN*3];
    unsigned char byte_fingerprint[SHA1_LEN];
    unsigned int byte_fingerprint_len;
    const EVP_MD *digest;
    const char * hex = "0123456789ABCDEF";

    digest = EVP_get_digestbyname("sha1");
    X509_digest(cert_objects[cert_number], digest, byte_fingerprint, &byte_fingerprint_len);

    int i;
    int j=0;
    for(i =0; i<SHA1_LEN-1; i++)
    {
        single_fingerprint[j] = hex[(byte_fingerprint[i]>>4) & 0xF];
        single_fingerprint[j+1] = hex[byte_fingerprint[i]& 0xF];
        single_fingerprint[j+2] = ':';
        j+=3;
    }
    single_fingerprint[j] = hex[(byte_fingerprint[i]>>4) & 0xF];
    single_fingerprint[j+1] = hex[byte_fingerprint[i]& 0xF];
    single_fingerprint[j+2]=0;

    return single_fingerprint;
}


bool X509RepBasicChainObject::is_in_CA(X509 *cert, X509_STORE* store)
{
    X509_STORE_CTX *verify_ctx;
    verify_ctx = X509_STORE_CTX_new();

    X509_STORE_CTX_cleanup(verify_ctx);
    if (X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1)
        FatalError("Error initializing verification context \n");

    int result = X509_verify_cert(verify_ctx);
    X509_STORE_CTX_free(verify_ctx);

    if(result==1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

bool X509RepBasicChainObject::full_CA_verify(string path)
{

}

bool X509RepBasicChainObject::is_self_signed(X509* cert)
{
    char * subject= X509_NAME_oneline(X509_get_subject_name(cert),0,0);
    char * issuer= X509_NAME_oneline(X509_get_issuer_name(cert),0,0);

    if(strcmp(subject, issuer)==0)
    {
        return 1;
    }

    return 0;
}

bool X509RepBasicChainObject::is_in_untrusted_CA()
{
    if(cert_objects.size()==0)
        return 0;

    bool result=is_in_CA(cert_objects[0], untrusted_CA_store);

    if(full_check==0)
    {
        return result;
    }
    else
    {
        if(result==0)
        {
            full_CA_verify(untrusted_CA_path);
        }
    }


}

bool X509RepBasicChainObject::is_in_trusted_CA()
{

    if(cert_objects.size()==0)
        return 0;

    bool result=is_in_CA(cert_objects[0], trusted_CA_store);

    if(full_check==0)
    {
        return result;
    }
    else
    {
        if(result==0)
        {
            full_CA_verify(trusted_CA_path);
        }
    }
}

X509_STORE* X509RepBasicChainObject::set_X509_STORE(string path)
{
    X509_STORE* store = X509_STORE_new();
    X509_LOOKUP* lookup;

    if ((X509_STORE_load_locations(store, NULL, path.c_str())) != 1)
    {
        FatalError("Error loading the CA file or directory \n");
    }

    if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())))
        FatalError("Error creating X509_LOOKUP object");

    //X509_LOOKUP_free(lookup);
    return store;
}

int X509RepBasicChainObject::set_Trusted_X509_STORE()
{
    trusted_CA_store = set_X509_STORE(trusted_CA_path);
}

int X509RepBasicChainObject::set_Untrusted_X509_STORE()
{
    untrusted_CA_store = set_X509_STORE(untrusted_CA_path);
}

char* X509RepBasicChainObject::get_subject_DN(int cert_number)
{
    if(cert_objects.size()<=cert_number)
        return NULL;

    return X509_NAME_oneline(X509_get_subject_name(cert_objects[cert_number]),0,0);
}

char* X509RepBasicChainObject::get_issuer_DN(int cert_number)
{
    if(cert_objects.size()<=cert_number)
        return NULL;

    return X509_NAME_oneline(X509_get_issuer_name(cert_objects[cert_number]),0,0);
}

int X509RepBasicChainObject::save_certificates(string path)
{
    int vector_len=cert_objects.size();
    string file_name= "";
    string cert_type=".pem";

    FILE *fp;

    for(int i=0; i<vector_len; i++)
    {
        stringstream index;
        index<<i;
        file_name=path+"/cert_"+index.str()+cert_type;

        fp = fopen(file_name.c_str(), "w+");
        PEM_write_X509(fp, cert_objects[i]);
        fclose(fp);
    }

    return 1;
}
