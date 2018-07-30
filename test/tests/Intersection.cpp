//
// Created by sauron on 7/27/18.
//
#include "gtest/gtest.h"
#include "server/query.h"
#include "source/genkey.h"
#include <NTL/ZZ_p.h>
#include <NTL/ZZ.h>

#define SETS_NO 2

class IntersectionTest: public testing::Test {

public:
    Key *k;
    void SetUp() {
        NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
        NTL::ZZ_p::init(p);
        k = new Key(p);
        // code here will execute just before the test ensues
    }

    void TearDown() {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

};

TEST_F (IntersectionTest, TwoSets) {
//    Intersection *i = new Intersection;
}

