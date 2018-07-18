//
// Created by sauron on 7/12/18.
//

#ifndef BILINEAR_SETUP_H
#define BILINEAR_SETUP_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <set>
#include "bn.h"
#include "test_point.hpp"
#include "genkey.h"

class DataStructure {
public:
    static const int m = 2;
    std::set<NTL::ZZ_p> D[m];
    bn::Ec1 AuthD[m];
    void setup(PublicKey*, SecretKey*);
    void insert(int index, NTL::ZZ_p, PublicKey*, SecretKey*);
};



#endif //BILINEAR_SETUP_H
