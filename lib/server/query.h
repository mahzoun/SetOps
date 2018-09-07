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
#include "utils/dbg.h"
#include "utils/querytree.h"

#define SETS_MAX_NO 2000
#define SETS_MAX_SIZE 10000
#define SMALL_QUERY_SIZE 2

class Query {
public:
    PublicKey *pk;
    DataStructure *dataStructure;
};

/*
 * The intersection class contains all functions and data needed to answer query
 * I is the result of intersection
 * indices is a vector of all sets in the query
 * W array contains subset witnesses and Q contains completeness witnesses
 */
class Intersection : Query {
public:
    std::set<NTL::ZZ_p, ZZ_p_compare> I;
    std::vector<int> indices;
    bn::Ec2 *W[SETS_MAX_NO];
    bn::Ec1 *Q[SETS_MAX_NO], *digest_I;
    NTL::vec_ZZ_p c;
    NTL::ZZ_pX p[SETS_MAX_NO], q[SETS_MAX_NO], polyA, polyB, polyS, polyT, polyD;

    Intersection();

    Intersection(std::vector<int>, PublicKey *, DataStructure *);

    ~Intersection();

    // Compute the bezout coefficients
    void xgcdTree();

    // Compute intersection
    void intersect();

    // Compute subset witnesses
    void subset_witness();

    // Compute completeness witnesses
    void completeness_witness();
};

/*
 * The union class contains all functions and data needed to answer query
 * U is the result of intersection
 * indices is a vector of all sets in the query
 * tree is a 2D vector containing the pointer to nodes of the tree
 */
class Union : Query {
public:
    std::vector<int> indices, set_indices;
    NTL::vec_ZZ_p c;
    NTL::ZZ_pX p1, p2, PolyD, PolyS, PolyT;
    std::set<NTL::ZZ_p, ZZ_p_compare> U;
    std::vector<std::vector<QueryNode>> tree;

    Union();

    Union(std::vector<int>, PublicKey *, DataStructure *);

    // calculate accumulation values for each set
    void setup_node(int, int);

    // answer the query
    void unionSets();

};

class Union2 : Query {
public:
    std::set<NTL::ZZ_p, ZZ_p_compare> U;
    // set_indices stores the index of set for each member of U
    std::vector<int> indices, set_indices;
    NTL::vec_ZZ_p c;
    // W1 is membership witness and W2 is superset
    bn::Ec2 *W1[SETS_MAX_SIZE];
    bn::Ec2 *W2[SETS_MAX_NO];
    NTL::ZZ_pX p;

    Union2();

    Union2(std::vector<int>, PublicKey *, DataStructure *);

    ~Union2();

    void unionSets();

    void membership_witness();

    void superset_witness();
};

/*
 * check if index[1] is the subset of index[0]
 */
class Subset : Query {
public:
    bool answer;
    int index[SMALL_QUERY_SIZE];
    bn::Ec2 *W;
    bn::Ec2 *Q[SMALL_QUERY_SIZE];
    NTL::vec_ZZ_p c, tmp_c;
    NTL::ZZ_p y;
    NTL::ZZ_pX p[SMALL_QUERY_SIZE], q[SMALL_QUERY_SIZE], polyD;

    Subset();

    Subset(int, int, PublicKey *, DataStructure *);

    ~Subset();

    void subset();

    void positiveWitness();

    void negativeWitness();
};

/*
 * This class contains the functions and data needed to prove difference queries
 * D is the difference and I is the W_i \ D which we want to prove is the intersection
 */
class Difference : Query {
public:
    std::set<NTL::ZZ_p, ZZ_p_compare> D, I;
    int index[2];
    bn::Ec2 *W[SMALL_QUERY_SIZE], *Wd;
    bn::Ec1 *Q[SMALL_QUERY_SIZE], *digest_D;
    NTL::vec_ZZ_p c;
    NTL::ZZ_pX p[SMALL_QUERY_SIZE], q[SMALL_QUERY_SIZE], polyD;

    Difference();

    Difference(int[], PublicKey *, DataStructure *);

    ~Difference();

    void difference();

    void witness();
};

#endif //BILINEAR_QUERY_H
