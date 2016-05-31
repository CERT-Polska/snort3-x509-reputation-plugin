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

#include <algorithm>
#include <set>
#include <vector>
#include <string>
#include <fstream>
#include "log/messages.h"

#include "x509rep_basic_fingerprint.h"

using namespace std;


BasicFingerprintContener::BasicFingerprintContener()
{
    black_list_path=NULL;
    white_list_path=NULL;
}

BasicFingerprintContener::~BasicFingerprintContener()
{
    delete [] black_list_path;
    delete [] white_list_path;
}

int BasicFingerprintContener::init(char* black_list_path, char* white_list_path, bool black_list_disable,bool white_list_disable, \
                                  std::vector<std::string> black_list_vector, std::vector<std::string> white_list_vector)
{
    this->black_list_path=black_list_path;
    this->white_list_path=white_list_path;
    this->black_list_disable=black_list_disable;
    this->white_list_disable=white_list_disable;

    if( !white_list_disable and white_list_path!=NULL)
    {
        get_data(white_list_path);
    }
    if( !black_list_disable and black_list_path!=NULL)
    {
        get_data(black_list_path);
    }

    get_fingerprints_from_vector(white_list_vector, &white_list);
    get_fingerprints_from_vector(black_list_vector, &black_list);
}

bool BasicFingerprintContener::is_in_white_list(string fingerprint)
{
    set<string>::iterator it=white_list.find(fingerprint);
    if(it!=white_list.end())
        return 1;

    return 0;
}

bool BasicFingerprintContener::is_in_black_list(string fingerprint)
{
    set<string>::iterator it=black_list.find(fingerprint);

    if(it!=black_list.end())
        return 1;

    return 0;
}

void BasicFingerprintContener::get_fingerprints_from_vector(vector<string> my_vector, set<string> *my_list)
{
    string fingerprint;
    int vector_len = my_vector.size();
    int j;

    for(int i=0; i<vector_len; i++)
    {
        fingerprint="";
        if(my_vector[i].size()!=SHA1_LEN*2)
        {
            FatalError("Incorrect fingerprint length ");
        }

        transform(my_vector[i].begin(), my_vector[i].end(), my_vector[i].begin(), ::toupper);

        for(j=0; j<SHA1_LEN*2-2; j+=2)
        {
            fingerprint= fingerprint + my_vector[i][j] + my_vector[i][j+1] + ":";
        }
        fingerprint=fingerprint+my_vector[i][j]+my_vector[i][j+1];
        my_list->insert(fingerprint);
    }
}


void BasicFingerprintContener::get_data(char * file_path)
{
    fstream file;
    set<string> * my_list;

    if(file_path==black_list_path)
    {
        my_list = &black_list;
    }
    else if(file_path==white_list_path)
    {
        my_list = &white_list;
    }

    string one_fingerprint;

    file.open(file_path, std::ios::in);

    if(file)
    {
        while(!file.eof())
        {
            getline(file, one_fingerprint);
            my_list->insert(one_fingerprint);
        }
    }
    else
    {
        FatalError("Can't open file: \n");
    }
}

