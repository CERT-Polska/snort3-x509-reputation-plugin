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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define SSL_ERROR_FLAGS \
    (SSL_BOGUS_HS_DIR_FLAG | \
    SSL_BAD_VER_FLAG | \
    SSL_BAD_TYPE_FLAG | \
    SSL_UNKNOWN_FLAG)

#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fstream>

#include "utils/util.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "x509rep_conf.h"
#include "x509rep_packet_info.h"
#include "x509rep_x509_chain_object.h"
#include "x509Rep_basic_chain_object.h"
#include "x509rep_SSL_decoder.h"
#include "x509rep_SSL_basic_decoder.h"
#include "x509rep_fingerprint.h"
#include "x509rep_basic_fingerprint.h"

static const char* s_name = "x509rep";
static const char* s_help = "X509 certificate validation system";

static THREAD_LOCAL ProfileStats x509RepPerfStats;
struct stat info;

using namespace std;

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class x509RepOption : public IpsOption
{
public:
    x509RepOption(x509Rep_config * session_config);
    ~x509RepOption();

private:
    fstream file;
    X509ChainObject* x509_chain_object;
    SSLDecoder *ssl_decoder;
    Packet_info *packet_info;
    x509Rep_config * session_config;
    FingerprintContener *fingerprint_contener;


    int eval(Cursor&, Packet*) override;
    void save_data_to_file(Packet_info *packet_info, string single_fingerprint, const char *detection_name, char * subject_DN, char * issuer_DN );
    void save_cert_to_file();
};

x509RepOption::x509RepOption(x509Rep_config * session_config) : IpsOption(s_name), session_config(session_config)
{
    ssl_decoder= new SSLBasicDecoder;
    x509_chain_object= new X509RepBasicChainObject;

    x509_chain_object->init(session_config->get_trusted_CA_path(), session_config->get_untrusted_CA_path(), session_config->get_trusted_CA_disable(), \
                            session_config->get_untrusted_CA_disable(), session_config->get_full_chain_verify());

    fingerprint_contener = new BasicFingerprintContener;
    fingerprint_contener->init(session_config->get_black_list_path(), session_config->get_white_list_path(), session_config->get_black_list_disable(), \
                               session_config->get_white_list_disable(), session_config->get_black_fingerprint_list(), session_config->get_white_fingerprint_list());

    packet_info = new Packet_info;
    char* logfile_path = session_config->get_logfile();
    if(logfile_path!=NULL)
    {
        file.open(logfile_path, ios::out);
        if(!file)
        {
            FatalError("Can't open file %s \n", logfile_path);
        }
    }
    delete [] logfile_path;
}

x509RepOption::~x509RepOption()
{
    delete x509_chain_object;
    delete ssl_decoder;
    delete packet_info;
    delete session_config;
    delete fingerprint_contener;
}


int x509RepOption::eval(Cursor&, Packet* p)
{
    Profile profile(x509RepPerfStats);

    if ( !(p->packet_flags & PKT_REBUILT_STREAM) && !p->is_full_pdu() )
        return DETECTION_OPTION_NO_MATCH;

    if (!p->flow)
        return DETECTION_OPTION_NO_MATCH;

    ssl_decoder->init(p);

    if(ssl_decoder->is_certificate())
    {
        x509_chain_object->set_chain(ssl_decoder->get_certificate_vector());

        char * single_fingerprint = x509_chain_object->get_cert_fingerprint(FIRST_CERTIFICATE);

        if(single_fingerprint==NULL)
            return DETECTION_OPTION_NO_MATCH;

        packet_info->set_src_ip_addr(p->ptrs.ip_api.get_src());
        packet_info->set_dst_ip_addr(p->ptrs.ip_api.get_dst());
        packet_info->set_time_info(p->pkth->ts);

        if (!(session_config->get_black_list_disable()) and fingerprint_contener->is_in_black_list(single_fingerprint))
        {
            save_data_to_file(packet_info, single_fingerprint, "CERT_FROM_BLACK_LIST",x509_chain_object->get_subject_DN(FIRST_CERTIFICATE), x509_chain_object->get_issuer_DN(FIRST_CERTIFICATE));
            save_cert_to_file();
            return DETECTION_OPTION_MATCH;
        }

        if (!session_config->get_white_list_disable() and fingerprint_contener->is_in_white_list(single_fingerprint))
        {
            return DETECTION_OPTION_NO_MATCH;
        }

        if (!session_config->get_untrusted_CA_disable())
        {
            if(x509_chain_object->is_in_untrusted_CA())
            {
                save_data_to_file(packet_info, single_fingerprint, " UNTRUSTED_CA_CERT ",x509_chain_object->get_subject_DN(FIRST_CERTIFICATE), x509_chain_object->get_issuer_DN(FIRST_CERTIFICATE));
                save_cert_to_file();
                return DETECTION_OPTION_MATCH;
            }
        }

        if (!session_config->get_trusted_CA_disable())
        {
            if(x509_chain_object->is_in_trusted_CA())
            {
                return DETECTION_OPTION_NO_MATCH;
            }
        }

        save_data_to_file(packet_info, single_fingerprint, " UNKNOWN_CERT ",x509_chain_object->get_subject_DN(FIRST_CERTIFICATE), x509_chain_object->get_issuer_DN(FIRST_CERTIFICATE));
        save_cert_to_file();

        return DETECTION_OPTION_MATCH;

    }

    return DETECTION_OPTION_NO_MATCH;
}

void x509RepOption::save_data_to_file(Packet_info *packet_info, string single_fingerprint, const char *detection_name, char * subject_DN, char * issuer_DN )
{
    char* log_file_path = session_config->get_logfile();
    if(log_file_path!=NULL)
    {
        file<<"[ "<<detection_name<<" ] "<<"[ TIME ] "<<packet_info->get_time_info()<<"  [ FINGERPRINT ] "<<single_fingerprint<<"  [ Subject DN ] "<<subject_DN<<" [ Issuer DN ] "<<issuer_DN<<"\n";
        file.flush();
    }
    delete [] log_file_path;
}


void x509RepOption::save_cert_to_file()
{
    if(session_config->get_save_cert_path()!=NULL)
    {
        char* save_cert_path=session_config->get_save_cert_path();
        string cert_file_name(save_cert_path);
        cert_file_name+="/";
        cert_file_name+=packet_info->get_hour();

        //If directory doesn't exist create it.
        if( stat( save_cert_path, &info ) != 0 )
            mkdir(save_cert_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

        if( stat( cert_file_name.c_str(), &info ) != 0 )
            mkdir(cert_file_name.c_str(),S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

        x509_chain_object->save_certificates(cert_file_name);
        delete [] save_cert_path;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "black_list_path", Parameter::PT_STRING, nullptr, nullptr, "Path to BlaskList fingerprints file" },
    { "white_list_path", Parameter::PT_STRING, nullptr, nullptr, "Path to WhiteList fingerprints file" },
    { "trusted_CA_path", Parameter::PT_STRING, nullptr, nullptr, "Path to TrustedCA information dictionary" },
    { "untrusted_CA_path", Parameter::PT_STRING, nullptr, nullptr, "Path to UntrustedCA information dictionary" },
    { "white_fingerprint", Parameter::PT_STRING, nullptr, nullptr, "Add single fingerprint to whitelist" },
    { "black_fingerprint", Parameter::PT_STRING, nullptr, nullptr, "Path to UntrustedCA information dictionary" },
    { "black_list_disable", Parameter::PT_INT, nullptr, nullptr, "Disable checking Black List, Default: on" },
    { "white_list_disable", Parameter::PT_INT, nullptr, nullptr, "Disable verifying certificate with certificates saved in given Trusted CA directory" },
    { "trusted_CA_disable", Parameter::PT_INT, nullptr, nullptr, "Disable verifying certificate with certificates saved in given Untrusted CA directory" },
    { "untrusted_CA_disable", Parameter::PT_INT, nullptr, nullptr, "Check TrustedCA dictionary, Default: on" },
    //{ "full_chain_verify", Parameter::PT_INT, nullptr, nullptr, "" },
    { "logfile", Parameter::PT_STRING, nullptr, nullptr, "Save log information to file" },
    { "save_cert", Parameter::PT_STRING, nullptr, nullptr, "Save suspicious certificates to folder" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class x509RepModule : public Module
{
public:
    x509RepModule() : Module(s_name, s_help, s_params) {}
    ~x509RepModule() {}

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &x509RepPerfStats;
    }

    x509Rep_config * session_config;
};

bool x509RepModule::begin(const char*, int, SnortConfig*)
{
    session_config = new x509Rep_config;
    return true;
}

bool x509RepModule::end(const char*, int, SnortConfig*)
{
    session_config->auto_set();
    session_config->check_session_config();

    return true;
}

bool x509RepModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("black_list_path"))
    {
        session_config->set_black_list_path(strdup(v.get_string()));
    }
    else if (v.is("white_list_path"))
    {
        session_config->set_white_list_path(strdup(v.get_string()));
    }
    else if (v.is("trusted_CA_path"))
    {
        session_config->set_trusted_CA_path(strdup(v.get_string()));
    }
    else if (v.is("untrusted_CA_path"))
    {
        session_config->set_untrusted_CA_path(strdup(v.get_string()));
    }
    else if (v.is("black_list_disable"))
    {
        session_config->set_black_list_disable(1);
    }
    else if (v.is("white_list_disable"))
    {
        session_config->set_white_list_disable(1);
    }
    else if (v.is("trusted_CA_disable"))
    {
        session_config->set_trusted_CA_disable(1);
    }
    else if (v.is("untrusted_CA_disable"))
    {
        session_config->set_untrusted_CA_disable(1);
    }
    else if (v.is("white_fingerprint"))
    {
        session_config->add_white_fingerprint(v.get_string());
    }
    else if (v.is("black_fingerprint"))
    {
        session_config->add_black_fingerprint(v.get_string());
    }
    else if (v.is("logfile"))
    {
        session_config->set_logfile(strdup(v.get_string()));
    }/*
    else if (v.is("full_chain_verify"))
    {
        session_config->set_full_chain_verify(1);
    }*/
    else if (v.is("save_cert"))
    {
        session_config->set_save_cert_path(strdup(v.get_string()));
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new x509RepModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* x509Rep_ctor(Module* p, OptTreeNode*)
{
    x509RepModule* m = (x509RepModule*)p;
    return new x509RepOption(m->session_config);
}

static void x509Rep_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi x509Rep_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    x509Rep_ctor,
    x509Rep_dtor,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &x509Rep_api.base,
    nullptr
};
