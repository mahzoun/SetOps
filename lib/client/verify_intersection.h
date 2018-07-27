//
// Created by sauron on 7/19/18.
//

#ifndef BILINEAR_VERIFY_INTERSECTION_H
#define BILINEAR_VERIFY_INTERSECTION_H
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZVec.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vector.h>
#include "bn.h"
#include "source/genkey.h"
#include "server/query.h"
#include "utils/utils.h"
#include "utils/merkletree.h"

class VerifyIntersection {
public:
    static int m;
    PublicKey *pk;
    //TODO calculate digest_I here :)
    bn::Ec1 digest_I;
    std::set<NTL::ZZ_p, ZZ_p_compare> I;
    bn::Ec2 *W[SETS_MAX_NO];
    bn::Ec1 *Q[SETS_MAX_NO];
    bn::Ec1 AuthD[SETS_MAX_NO];
    VerifyIntersection(PublicKey*, bn::Ec1, std::set<NTL::ZZ_p, ZZ_p_compare>, bn::Ec2*[], bn::Ec1*[], bn::Ec1[], int);
    VerifyIntersection(PublicKey*, bn::Ec1, std::vector<NTL::ZZ_p>, bn::Ec2*[], bn::Ec1*[], bn::Ec1[], int);
    bool verify_intersection();
    bool verify_tree();
};


#endif //BILINEAR_VERIFY_INTERSECTION_H
