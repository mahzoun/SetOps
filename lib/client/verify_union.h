//
// Created by sauron on 8/2/18.
//

#ifndef BILINEAR_VERIFY_UNION_H
#define BILINEAR_VERIFY_UNION_H
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
#include "client/verify_intersection.h"

class VerifyUnion {
public:
    int m;
    PublicKey *pk;
    std::vector<int> indices;
    bn::Ec1 digest_U;
    std::set<NTL::ZZ_p, ZZ_p_compare> union_ans;
    std::vector<NTL::ZZ_p> U;
    std::vector<std::vector<QueryNode>> tree;

    VerifyUnion(PublicKey *, std::set<NTL::ZZ_p, ZZ_p_compare>, std::vector<std::vector<QueryNode>>&, int, std::vector<int>&);
    bool verified_intersection();
    bool verify_union();
};

#endif //BILINEAR_VERIFY_UNION_H
