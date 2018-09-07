//
// Created by sauron on 8/6/18.
//

#ifndef BILINEAR_VERIFY_SUBSET_H
#define BILINEAR_VERIFY_SUBSET_H

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
 * check if J is subset of I
 * W is subset witness
 * Q is the witness to show the subset witness
 * y is the member to prove negative result
 */
class VerifySubset {
public:
    bool answer, verified_subset;
    int I, J;
    PublicKey *pk;
    DataStructure *dataStructure;
    bn::Ec2 *W;
    bn::Ec2 *Q[2];
    bn::Ec1 AuthD[SETS_MAX_NO];
    NTL::ZZ_p y;

    VerifySubset(PublicKey *, DataStructure *, bn::Ec2 *[], bn::Ec2 *, bool, int, int, NTL::ZZ_p);

    void verify_subset();

    bool verifyPositive();

    bool verifyNegetive();
};

#endif //BILINEAR_VERIFY_SUBSET_H
