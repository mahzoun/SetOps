//
// Created by sauron on 7/17/18.
//

#ifndef BILINEAR_UTILS_H
#define BILINEAR_UTILS_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include <string>
#include <sstream>
#include <set>
#include "source/genkey.h"

#include "bn.h"

class Utils {
public:
    bn::Ec1 compute_digest(std::multiset<int>, const bn::Ec1, SecretKey *);
    bn::Ec1 compute_digest_pub(std::multiset<int> , const bn::Ec1, PublicKey *);
    char* Ec1ToString(bn::Ec1);
    char* concat(const char*, const char*);
    unsigned char* sha256(char*);
    NTL::ZZ_p StringToz(char*);
};

//char* zToString(NTL::ZZ_p);

#endif //BILINEAR_UTILS_H
