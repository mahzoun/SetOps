//
// Created by sauron on 7/18/18.
//

#ifndef BILINEAR_QUERY_H
#define BILINEAR_QUERY_H

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

class Query{
public:
    int index;
    PublicKey *pk;
    DataStructure *dataStructure;
    void setup();
    void beta();
    void gamma();
};

class Intersection: Query{
public:
    std::set<int> I;
    std::vector<int> indices;
    bn::Ec2 *W1, *W2;
    bn::Ec1 *Q1, *Q2, *digest_I;
    NTL::vec_ZZ_p c;
    NTL::ZZ_pX polyA,polyB,polyS,polyT,polyD;
    Intersection();
    Intersection(std::vector<int>, PublicKey*, DataStructure*);
    void intersect();
    void subset_witness();
    void completeness_witness();
};

#endif //BILINEAR_QUERY_H
