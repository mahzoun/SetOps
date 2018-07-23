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
#include "utils/utils.h"
#include "utils/merkletree.h"

#define SETS_MAX_NO 1000

struct ZZ_p_compare {
public:
    bool operator()(const NTL::ZZ_p&, const NTL::ZZ_p&) const;
};

class DataStructure {
public:
    static int m;
    //TODO change set to sorted vector :-?
    std::set<int> D[SETS_MAX_NO];
    bn::Ec1 AuthD[SETS_MAX_NO];
    //TODO optimize memory :)
    bn::Ec1 digest[SETS_MAX_NO][SETS_MAX_NO], beta[SETS_MAX_NO][SETS_MAX_NO], gamma[SETS_MAX_NO][SETS_MAX_NO];
    DataStructure();
    DataStructure(int);
    void setup(PublicKey*, SecretKey*);
    void treeDigest(PublicKey*, SecretKey *);
    bn::Ec1 calNodeDigest(PublicKey *, SecretKey*, bn::Ec1, bn::Ec1);
    void insert(int, int, PublicKey*, SecretKey*);
};



#endif //BILINEAR_SETUP_H
