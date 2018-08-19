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
#include <string>
#include "bn.h"
#include "test_point.hpp"
#include "utils/utils.h"
#include "utils/dbg.h"
#include <cstdlib>

class SecretKey{
public:
    NTL::ZZ_p sk;
    SecretKey();
    SecretKey(NTL::ZZ_p);
};

class PublicKey{
public:
    std::vector<bn::Ec1> pubs_g1;
    std::vector<bn::Ec2> pubs_g2;
    bn::Ec1 g1;
    bn::Ec2 g2;
    PublicKey(NTL::ZZ p);
    ~PublicKey();
    void setup_bilinear(SecretKey*, bn::Ec1, bn::Ec2);
    //NTL::ZZ_p h(bn::Ec1);

};


class Key{
public:
    PublicKey* get_public_key();
    SecretKey* get_secret_key();
    Key();
    Key(NTL::ZZ);
    ~Key();
private:
    PublicKey *pk;
    SecretKey *sk;
    void genkey(NTL::ZZ);
    void create_public_key(SecretKey*, NTL::ZZ);
};


#endif //BILINEAR_GENKEY_H
