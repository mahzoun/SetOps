//
// Created by sauron on 7/27/18.
//
#include "gtest/gtest.h"
#include "server/query.h"
#include "source/genkey.h"
#include "client/verify_union.h"
#include "client/verify_tree.h"
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <exception>

#define SETS_NUM 2
#define size 10


class UnionTest: public ::testing::Test{
protected:
    Key *k;
    DataStructure *dataStructure;
    std::vector<int> v;
    Union *un;
    VerifyTree *verifyTree;
    VerifyUnion *verifyUnion;
    void SetUp(int sets_no) {
        try {
            NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
            NTL::ZZ_p::init(p);
            k = new Key(p);
            dataStructure = new DataStructure(sets_no, k);
            for (int i = 1; i <= size; i++) {
                NTL::ZZ_p j = NTL::random_ZZ_p();
                for (int set_index = 0; set_index < dataStructure->m; set_index++) {
                    dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
                }
            }
            for (int set_index = 0; set_index < dataStructure->m; set_index++)
                for (int i = 1; i <= 9 * size / 10; i++) {
                    NTL::ZZ_p j = NTL::random_ZZ_p();
                    dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
                }

            for (int set_index = 0; set_index < dataStructure->m; set_index++)
                v.push_back(set_index);
        }
        catch(std::exception& e){
            std::cerr<< e.what() << "\n";
        }


    }
};

TEST_F(UnionTest, TwoSets) {
    SetUp(SETS_NUM);
    un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    un->membership_witness();
    un->superset_witness();
    verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
    verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD, dataStructure->m, v, un->set_indices);
    bool b = verifyUnion->verify_union();
    EXPECT_TRUE(b);
    EXPECT_TRUE(verifyUnion->membershipwitness);
    EXPECT_TRUE(verifyUnion->supersetnesswitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}

TEST_F(UnionTest, WrongMembershipWitness) {
    SetUp(SETS_NUM);
    un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    un->membership_witness();
    un->superset_witness();
    verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
    un->W1[0] += 1;
    verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD, dataStructure->m, v, un->set_indices);
    bool b = verifyUnion->verify_union();
    EXPECT_FALSE(b);
    EXPECT_FALSE(verifyUnion->membershipwitness);
    EXPECT_FALSE(verifyUnion->supersetnesswitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}

TEST_F(UnionTest, WrongSupersetWitness) {
    SetUp(SETS_NUM);
    un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    un->membership_witness();
    un->superset_witness();
    verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
    un->W2[0] += 1;
    verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD, dataStructure->m, v, un->set_indices);
    bool b = verifyUnion->verify_union();
    EXPECT_FALSE(b);
    EXPECT_TRUE(verifyUnion->membershipwitness);
    EXPECT_FALSE(verifyUnion->supersetnesswitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}

TEST_F(UnionTest, MultipleSets){
    SetUp(6);
    v.clear();
    for(int set_index = 0; set_index < dataStructure->m; set_index+=2)
        v.push_back(set_index);
    un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    un->membership_witness();
    un->superset_witness();
    verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD, dataStructure->m, v, un->set_indices);
    bool b = verifyUnion->verify_union();
    EXPECT_TRUE(b);
    EXPECT_TRUE(verifyUnion->membershipwitness);
    EXPECT_TRUE(verifyUnion->supersetnesswitness);
    EXPECT_TRUE(verifyTree->verifiedtree);
}