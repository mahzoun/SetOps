//
// Created by sauron on 7/17/18.
//

#ifndef BILINEAR_UTILS_H
#define BILINEAR_UTILS_H
#define NODEBUG

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include <string>
#include <sstream>
#include <set>
#include <openssl/sha.h>
#include "source/genkey.h"
#include "bn.h"

#define SET_MAX_NO 2000
#define SET_NO_LEN 12

class SecretKey;

class PublicKey;

//class to compare two ZZ_p elements
class ZZ_p_compare {
public:
    bool operator()(const NTL::ZZ_p &, const NTL::ZZ_p &) const;
};

class Utils {
public:
    //compute the digest of a set with access to secret key
    bn::Ec1 compute_digest(std::set<NTL::ZZ_p, ZZ_p_compare>, const bn::Ec1, SecretKey *);

    //compute the digest of a set with no access to secret key (Ec1)
    bn::Ec1 compute_digest_pub(std::set<NTL::ZZ_p, ZZ_p_compare>, const bn::Ec1, PublicKey *);

    //compute the digest of a set with no access to secret key (Ec2)
    bn::Ec2 compute_digest_pub(std::set<NTL::ZZ_p, ZZ_p_compare>, const bn::Ec2, PublicKey *);

    //compute the digest*a of a set with no access to secret key (Ec2)
    bn::Ec2 compute_digest_puba(std::set<NTL::ZZ_p, ZZ_p_compare>, const bn::Ec2, PublicKey *);

    //convert elements in Ec1 to string
    char *Ec1ToString(bn::Ec1);

    //convert elements in Ec2 to string
    char *Ec2ToString(bn::Ec2);

    //return a char* which is the concatenation of two inputs
    char *concat(const char *, const char *);

    //compute the hash of second argument and write it to first argument
    void sha256(unsigned char *, char *);
    //compute the hash of second argument and write it to first argument, this function is used by merkle tree to hash leafes
    void sha256(unsigned char *, char *, int);

    //convert strings to ZZ_p
    NTL::ZZ_p StringToz(char *);

    //convert ZZ_p to char*
    char *zToString(NTL::ZZ_p &);

    //convert const ZZ_p to char*
    char *zToString(const NTL::ZZ_p &);
};

#endif //BILINEAR_UTILS_H
