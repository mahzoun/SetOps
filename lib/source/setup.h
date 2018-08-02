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

#define SETS_MAX_NO 2000
#define MERKLE_TREE_DEG 2


class MerkleTree;

class DataStructure {
public:
    int m;
    int depth;
    DataStructure();
    DataStructure(int, Key*);
    void treeDigest(PublicKey*, SecretKey *);
    bn::Ec1 calNodeDigest(PublicKey *, SecretKey*, bn::Ec1, bn::Ec1);
    void insert(int, NTL::ZZ_p, PublicKey*, SecretKey*);
    std::set<NTL::ZZ_p, ZZ_p_compare> D[SETS_MAX_NO];
    bn::Ec1 AuthD[SETS_MAX_NO];
    bn::Ec1 digest[SETS_MAX_NO][SETS_MAX_NO]; //, gamma[SETS_MAX_NO][SETS_MAX_NO][MERKLE_TREE_DEG];
    MerkleTree *merkleTree;
private:
    void setup(PublicKey*, SecretKey*);
};



#endif //BILINEAR_SETUP_H
