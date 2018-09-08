//
// Created by sauron on 7/24/18.
//

#ifndef BILINEAR_VERIFY_TREE_H
#define BILINEAR_VERIFY_TREE_H
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include "bn.h"
#include "source/genkey.h"
#include "server/query.h"
#include "utils/utils.h"
#include "utils/merkletree.h"

/*
 * The class to verify the integrity of the sets by using a Merkle tree
 */
class VerifyTree {
public:
    static int m;
    PublicKey *pk;
    bool verifiedtree;
    std::set<int> I;
    VerifyTree();
    void verifyTree(DataStructure *, std::vector<int>);
};

#endif //BILINEAR_VERIFY_TREE_H
