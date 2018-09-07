//
// Created by sauron on 8/19/18.
//

#ifndef BILINEAR_QUERYTREE_H
#define BILINEAR_QUERYTREE_H

#include <set>
#include <vector>
#include <algorithm>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include "bn.h"
#include "test_point.hpp"
#include "source/setup.h"
#include "utils/utils.h"
#include "utils/merkletree.h"
#include "utils/dbg.h"

#define SETS_MAX_NO 2000
#define SETS_MAX_SIZE 10000
#define SMALL_QUERY_SIZE 2

/*
 * This class used by fast union query, it's a node of tree built in union query
 * U is the union of the childs
 * I is the intersection of the childs
 * F1 and F2 are the accumulation values of the set
 * HI = acc(I) and HU = acc(U) HUp = digest using puba
 * W and Q are witnesses for proving intersection
 */
class QueryNode {
public:
    std::set<NTL::ZZ_p, ZZ_p_compare> SET, U, I;
    bn::Ec1 F1;
    bn::Ec2 F2;
    bn::Ec1 HI;
    bn::Ec2 HU, HUp, HIp;
    bn::Ec1 Q[SMALL_QUERY_SIZE];
    bn::Ec2 W[SMALL_QUERY_SIZE];
};


#endif //BILINEAR_QUERYTREE_H

