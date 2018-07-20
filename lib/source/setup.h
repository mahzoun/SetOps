//
// Created by sauron on 7/12/18.
//

#ifndef BILINEAR_SETUP_H
#define BILINEAR_SETUP_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include <set>
#include "bn.h"
#include "test_point.hpp"
#include "source/genkey.h"
#include "utils.h"

struct ZZ_p_compare {
public:
    bool operator()(const NTL::ZZ_p&, const NTL::ZZ_p&) const;
};

class DataStructure {
public:
    static const int m = 2;
    std::set<int> D[m];
    bn::Ec1 AuthD[m];
    void setup(PublicKey*, SecretKey*);
    void insert(int, int, PublicKey*, SecretKey*);
};



#endif //BILINEAR_SETUP_H
