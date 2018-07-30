//
// Created by sauron on 7/27/18.
//
#include "gtest/gtest.h"
#include "source/genkey.h"
#include "source/Intersection.h"
#define SETS_NO 2

TEST (SetupTest, SetupTwoSets) {
    const int size = 100;
    Key *k = new Key;
    NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    k->genkey(p);

    DataStructure *dataStructure = new DataStructure(SETS_NO);
    dataStructure->setup(k->get_public_key(), k->get_secret_key());
    for (int i = 1; i <= size / 10; i++) {
        NTL::ZZ_p j = NTL::random_ZZ_p();
        for (int set_index = 0; set_index < dataStructure->m; set_index++) {
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    for (int set_index = 0; set_index < dataStructure->m; set_index++){
        for (int i = 1; i <= 9 * size / 10; i++) {
            NTL::ZZ_p j = NTL::random_ZZ_p();
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    ASSERT_EQ(dataStructure->m, size);
}

