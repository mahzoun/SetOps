//
// Created by sauron on 7/19/18.
//

#ifndef BILINEAR_VERIFY_DIFFERENCE_H
#define BILINEAR_VERIFY_DIFFERENCE_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include "bn.h"
#include "source/genkey.h"
#include "server/query.h"
#include "utils/utils.h"
/*
 * Verify difference
 * D is the difference and I is W_i \ D
 * *W and *Q are the witnesses to show that I is the intersection
 */
class VerifyDifference {
public:
    PublicKey *pk;
    DataStructure *dataStructure;
    int index[SMALL_QUERY_SIZE];
    std::set<NTL::ZZ_p, ZZ_p_compare> D, I;
    bn::Ec2 *W[SMALL_QUERY_SIZE], *Wd;
    bn::Ec1 *Q[SMALL_QUERY_SIZE];
    bn::Ec1 digest_D, digest_I;
    bool verified_witness;

    VerifyDifference(PublicKey *, DataStructure *, std::set<NTL::ZZ_p, ZZ_p_compare>, std::set<NTL::ZZ_p, ZZ_p_compare>,
                     bn::Ec2 *[], bn::Ec2 *, bn::Ec1 *[], int[]);

    bool verify_difference();
};


#endif