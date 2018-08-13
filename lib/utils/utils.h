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

class SecretKey;
class PublicKey;

class ZZ_p_compare {
public:
    bool operator()(const NTL::ZZ_p&, const NTL::ZZ_p&) const;
//    bool operator<(NTL::ZZ_p&, NTL::ZZ_p&) const;
};

class Utils {
public:
    bn::Ec1 compute_digest(std::set<NTL::ZZ_p, ZZ_p_compare>, const bn::Ec1, SecretKey *);
    bn::Ec1 compute_digest_pub(std::set<NTL::ZZ_p, ZZ_p_compare> , const bn::Ec1, PublicKey *);
    bn::Ec1 compute_digest(std::vector<NTL::ZZ_p>, const bn::Ec1, SecretKey *);
    bn::Ec1 compute_digest_pub(std::vector<NTL::ZZ_p> , const bn::Ec1, PublicKey *);
    char* Ec1ToString(bn::Ec1);
    char* concat(const char*, const char*);
    void sha256(unsigned char*, char*);
    NTL::ZZ_p StringToz(char*);
    char* zToString(NTL::ZZ_p&);
    char* zToString(const NTL::ZZ_p&);
};

#endif //BILINEAR_UTILS_H
