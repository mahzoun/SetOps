//
// Created by sauron on 7/12/18.
//

#ifndef BILINEAR_GENKEY_H
#define BILINEAR_GENKEY_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <openssl/sha.h>
#include <exception>
#include <vector>
#include "bn.h"
#include "test_point.hpp"

char* zToString(NTL::ZZ_p&);

class SecretKey{
public:
    NTL::ZZ_p sk;
};

class PublicKey{
public:
    std::vector<bn::Ec1> pubs_g1;
    std::vector<bn::Ec2> pubs_g2;
    bn::Ec1 g1;
    bn::Ec2 g2;
    PublicKey(SecretKey*, NTL::ZZ p);
    void setup_bilinear(SecretKey*, bn::Ec1, bn::Ec2);
    //NTL::ZZ_p h(bn::Ec1);

};


class Key{
public:
    PublicKey* get_public_key();
    SecretKey* get_secret_key();
    void genkey(NTL::ZZ);
private:
    PublicKey *pk;
    SecretKey *sk;
    void create_public_key(SecretKey*, NTL::ZZ);
    void create_secret_key(SecretKey*, NTL::ZZ);

};


#endif //BILINEAR_GENKEY_H
