//
// Created by sauron on 7/27/18.
//
#include "gtest/gtest.h"
#include "server/query.h"
#include "source/genkey.h"
#include "client/verify_intersection.h"
#include "client/verify_tree.h"
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>

#define SETS_NO 2
#define size 100


class IntersectionTest: public ::testing::Test{
protected:
    Key *k;
    DataStructure *dataStructure;
    std::vector<int> v;
    Intersection *intersection;
    VerifyTree *verifyTree;
    VerifyIntersection *verifyIntersection;
    void SetUp(int intersectionSize) {
        NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
        NTL::ZZ_p::init(p);
        k = new Key(p);
        dataStructure = new DataStructure(SETS_NO, k);
        for(int i = 1; i <= intersectionSize; i++) {
            NTL::ZZ_p j = NTL::random_ZZ_p();
            for(int set_index = 0; set_index < dataStructure->m; set_index++) {
                dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
            }
        }
        for(int set_index = 0; set_index < dataStructure->m; set_index++)
            for(int i = 1; i <= 9*size/10; i++) {
                NTL::ZZ_p j = NTL::random_ZZ_p();
                dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
            }

        for(int set_index = 0; set_index < dataStructure->m; set_index++)
            v.push_back(set_index);

        intersection = new Intersection(v, k->get_public_key(), dataStructure);
        intersection->intersect();
        intersection->subset_witness();
        intersection->completeness_witness();
        verifyTree = new VerifyTree;
        verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
        //verify intersection
        verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W, intersection->Q, dataStructure->AuthD, dataStructure->m);

    }
};

TEST_F(IntersectionTest, TwoSets) {
    SetUp(size/10);
    bool b = verifyIntersection->verify_intersection();
    EXPECT_TRUE(b);
    EXPECT_TRUE(verifyIntersection->completenesswitness);
    EXPECT_TRUE(verifyIntersection->subsetwitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}

TEST_F(IntersectionTest, WrongsubsetWitness) {
    SetUp(size/10);
    intersection->W[0] += 1;
    verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W, intersection->Q, dataStructure->AuthD, dataStructure->m);
    bool b = verifyIntersection->verify_intersection();
    EXPECT_FALSE(b);
    EXPECT_FALSE(verifyIntersection->completenesswitness);
    EXPECT_FALSE(verifyIntersection->subsetwitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}

TEST_F(IntersectionTest, WrongCompletenessWitness) {
    SetUp(size/10);
    intersection->Q[0] += 1;
    verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W, intersection->Q, dataStructure->AuthD, dataStructure->m);
    bool b = verifyIntersection->verify_intersection();
    EXPECT_FALSE(b);
    EXPECT_FALSE(verifyIntersection->completenesswitness);
    EXPECT_TRUE(verifyIntersection->subsetwitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}

TEST_F(IntersectionTest, EmptySet){
    SetUp(0);
    verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W, intersection->Q, dataStructure->AuthD, dataStructure->m);
    bool b = verifyIntersection->verify_intersection();
    EXPECT_TRUE(b);
    EXPECT_TRUE(verifyIntersection->completenesswitness);
    EXPECT_TRUE(verifyIntersection->subsetwitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}
