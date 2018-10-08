//
// Created by sauron on 7/12/18.
//

#ifndef BILINEAR_GENKEY_H
#define BILINEAR_GENKEY_H

#include <openssl/sha.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <exception>
#include <cstdlib>
#include <vector>
#include <string>
#include "test_point.hpp"
#include "utils/utils.h"
#include "utils/dbg.h"
#include "bn.h"

using namespace std;

// Secret key class contains s, which is a random ZZ_p element
class SecretKey {
public:
    NTL::ZZ_p sk, a;

    SecretKey();

    SecretKey(NTL::ZZ_p, NTL::ZZ_p);
};

//Public key contains the power of g1^s and g2^s where g1 and g2 are generators from ate-pairing library
class PublicKey {
public:
    vector<bn::Ec1> pubs_g1;
    vector<bn::Ec2> pubs_g2;
    vector<bn::Ec1> pubs_ga1;
    vector<bn::Ec2> pubs_ga2;
    bn::Ec1 g1;
    bn::Ec2 g2;

    PublicKey(NTL::ZZ p);

    ~PublicKey();

    void setup_bilinear(SecretKey *, bn::Ec1, bn::Ec2);

};

//Key class which creates secret key and public key
class Key {
public:
    PublicKey *get_public_key();

    SecretKey *get_secret_key();

    Key();

    Key(NTL::ZZ);

    ~Key();

private:
    PublicKey *pk;
    SecretKey *sk;

    void genkey(NTL::ZZ);

    void create_public_key(SecretKey *, NTL::ZZ);

    void create_secret_key();
};


#endif //BILINEAR_GENKEY_H
