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
    bn::Ec1 compute_digest_pub(std::set<int> , const bn::Ec1, PublicKey *);
};

//char* zToString(NTL::ZZ_p);

#endif //BILINEAR_UTILS_H
