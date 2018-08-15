//
// Created by sauron on 8/6/18.
//

#include "gtest/gtest.h"
#include "server/query.h"
#include "source/genkey.h"
#include "client/verify_subset.h"
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>
#include <exception>
#define SETS_NUM 16
#define SIZE 10

class SubsetTest: public ::testing::Test{
protected:
    Key *k;
    DataStructure *dataStructure;
    Subset *subset;
    VerifySubset *verifySubset;
    void SetUp(int sets_no) {
        try {
            NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
            NTL::ZZ_p::init(p);
            k = new Key(p);
            dataStructure = new DataStructure(sets_no, k);
            for (int i = 1; i <= SIZE; i++) {
                NTL::ZZ_p j = NTL::random_ZZ_p();
                for (int set_index = 0; set_index < dataStructure->m; set_index++) {
                    dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
                }
            }
            for (int set_index = 1; set_index < dataStructure->m; set_index++)
                for (int i = 1; i <= 9 * SIZE / 10; i++) {
                    NTL::ZZ_p j = NTL::random_ZZ_p();
                    dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
                    dataStructure->insert(0, j, k->get_public_key(), k->get_secret_key());
                }

        }
        catch(std::exception& e){
            std::cerr<< e.what() << "\n";
        }


    }
    void TearDown() {
//        PUT(verifySubset->verified_subset);
//        delete (verifySubset);
//        delete (subset);
        delete (dataStructure);
        delete (k);
    }
};

TEST_F(SubsetTest, PositiveAnswer) {
    SetUp(SETS_NUM);
    Subset *subset = new Subset(0, 3, k->get_public_key(), dataStructure);
    subset->subset();
    if(subset->answer)
        subset->positiveWitness();
    else
        subset->negativeWitness();

    VerifySubset *verifySubset = new VerifySubset(k->get_public_key(), dataStructure, subset->Q, subset->W, subset->answer,
                                                  subset->index[0], subset->index[1], subset->y);
    verifySubset->verify_subset();
    EXPECT_TRUE(subset->answer);
    EXPECT_TRUE(verifySubset->verified_subset);
    delete verifySubset;
    delete subset;
}

TEST_F(SubsetTest, NegativeAnswer) {
    SetUp(SETS_NUM);
    Subset *subset = new Subset(2, 3, k->get_public_key(), dataStructure);
    subset->subset();
    if(subset->answer)
        subset->positiveWitness();
    else
        subset->negativeWitness();

    VerifySubset *verifySubset = new VerifySubset(k->get_public_key(), dataStructure, subset->Q, subset->W, subset->answer,
                                                  subset->index[0], subset->index[1], subset->y);
    verifySubset->verify_subset();
    EXPECT_FALSE(subset->answer);
    EXPECT_TRUE(verifySubset->verified_subset);
    delete verifySubset;
    delete subset;
}


TEST_F(SubsetTest, SameSets) {
    SetUp(SETS_NUM);
    Subset *subset = new Subset(2, 2, k->get_public_key(), dataStructure);
    subset->subset();
    if(subset->answer)
        subset->positiveWitness();
    else
        subset->negativeWitness();

    VerifySubset *verifySubset = new VerifySubset(k->get_public_key(), dataStructure, subset->Q, subset->W, subset->answer,
                                                  subset->index[0], subset->index[1], subset->y);
    verifySubset->verify_subset();
    EXPECT_TRUE(subset->answer);
    EXPECT_TRUE(verifySubset->verified_subset);
    delete verifySubset;
    delete subset;
}


