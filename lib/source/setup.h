//
// Created by sauron on 7/12/18.
//

#ifndef BILINEAR_SETUP_H
#define BILINEAR_SETUP_H
//#define NODEBUG

#include <set>
#include <map>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include "bn.h"
#include "test_point.hpp"
#include "source/genkey.h"
#include "utils/utils.h"
#include "utils/merkletree.h"

#define SETS_MAX_NO 2000

class MerkleTree;

/*
 * DataStructure class is a class in source which contains set collection and basic algorithms on set like
 * insertion and deletion
 * The accumulation value for each set is a member of EC and stores in AuthD array
 * Sets are std::set<ZZ_p, cmp> which cmp is a comparison function between ZZ_p elements
 */
class DataStructure {
public:
    int m;

    DataStructure();

    DataStructure(int, Key *);

    ~DataStructure();

    std::map<NTL::ZZ_p, int, ZZ_p_compare> set_index;

    void insert(int, NTL::ZZ_p, PublicKey *, SecretKey *);

    std::set<NTL::ZZ_p, ZZ_p_compare> D[SETS_MAX_NO];
    bn::Ec1 AuthD[SETS_MAX_NO];
    MerkleTree *merkleTree;
private:
    void setup(PublicKey *, SecretKey *);
};


#endif //BILINEAR_SETUP_H
