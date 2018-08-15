//
// Created by sauron on 8/6/18.
//

#include "gtest/gtest.h"
#include "server/query.h"
#include "client/verify_difference.h"

#define SETS_NUM 16
#define SIZE 10

class DifferenceTest : public ::testing::Test {
protected:
    Key *k;
    DataStructure *dataStructure;
    Difference *difference;
    VerifyDifference *verifyDifference;

    void SetUp(int sets_no) {
        try {
            NTL::ZZ p = NTL::conv<NTL::ZZ>(
                    "16798108731015832284940804142231733909759579603404752749028378864165570215949");
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
        catch (std::exception &e) {
            std::cerr << e.what() << "\n";
        }


    }
    void TearDown() {
        delete (dataStructure);
        delete (k);
    }
};

TEST_F(DifferenceTest, TwoSets1) {
    SetUp(SETS_NUM);
    int index[2];
    index[0] = 0;
    index[1] = 1;
    Difference *difference = new Difference(index, k->get_public_key(), dataStructure);
    difference->difference();
    difference->witness();

    VerifyDifference *verifyDifference = new VerifyDifference(k->get_public_key(), dataStructure, difference->D,
                                                              difference->I, difference->W, difference->Wd,
                                                              difference->Q, difference->index);
    verifyDifference->verify_difference();
    verifyDifference->verify_difference();
    EXPECT_TRUE(verifyDifference->verified_witness);
    delete (verifyDifference);
    delete (difference);
}

TEST_F(DifferenceTest, TwoSets2) {
    SetUp(SETS_NUM);
    int index[2];
    index[0] = 3;
    index[1] = 6;
    Difference *difference = new Difference(index, k->get_public_key(), dataStructure);
    difference->difference();
    difference->witness();

    VerifyDifference *verifyDifference = new VerifyDifference(k->get_public_key(), dataStructure, difference->D,
                                                              difference->I, difference->W, difference->Wd,
                                                              difference->Q, difference->index);
    verifyDifference->verify_difference();
    verifyDifference->verify_difference();
    EXPECT_TRUE(verifyDifference->verified_witness);
    delete (verifyDifference);
    delete (difference);
}
