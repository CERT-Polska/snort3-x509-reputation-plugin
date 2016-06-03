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
#include <iostream>

#include "ssl.h"
#include "x509rep_SSL_basic_decoder.h"

using namespace std;

SSLBasicDecoder::SSLBasicDecoder()
{
    all_certificates="";
    all_data=-1;
}

SSLBasicDecoder::~SSLBasicDecoder()
{
}

int SSLBasicDecoder::init(Packet* p)
{
    this->p=p;
    cert_buffer.clear();
    SSL_decode_with_cert(p->data, (int)p->dsize, p->packet_flags, 0, NULL, NULL, 0, all_certificates, all_data);
    if(all_certificates.size()>0)
    {
        decode_cert_string(all_certificates);
    }
    all_certificates="";
}

int SSLBasicDecoder::is_certificate()
{
    return !(cert_buffer.empty());
}

vector<string> SSLBasicDecoder::get_certificate_vector()
{
    return cert_buffer;
}

int SSLBasicDecoder::decode_cert_string(string all_certificates)
{
    int all_certyficats_len = ((unsigned char)all_certificates[4]<< 16) | ((unsigned char)all_certificates[5] << 8) | (unsigned char)all_certificates[6];
    int16_t single_cert_len;
    string single_cert_data="";
    int current_position=7;
    while(current_position<all_certyficats_len)
    {
        int mark_number=0;
        single_cert_len = ((unsigned char)all_certificates[current_position]<<16) | ((unsigned char)all_certificates[current_position+1]<<8) | ((unsigned char)all_certificates[current_position+2]);

        current_position+=3;
        for(single_cert_len; single_cert_len>0; single_cert_len--)
        {
            single_cert_data+=all_certificates[current_position];

            mark_number++;
            current_position++;
        }
        cert_buffer.push_back(single_cert_data);
        single_cert_data="";
    }

    return 1;
}

void SSLBasicDecoder::get_data()
{
    const uint8_t* pb = p->data;
    const uint8_t* end = p->data + p->dsize;

    if ( !(p->dsize) )
        return;

    while ( pb < end )
    {
        char b = pb[0];
        all_certificates+=pb[0];
        pb++;
    }
}
