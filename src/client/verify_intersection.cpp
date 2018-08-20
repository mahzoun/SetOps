//
// Created by sauron on 7/19/18.
//

#include "client/verify_intersection.h"

int VerifyIntersection::m = 2;

VerifyIntersection::VerifyIntersection(PublicKey *pk, std::set<NTL::ZZ_p, ZZ_p_compare> I, bn::Ec2 *W[], bn::Ec1 *Q[],
                                       bn::Ec1 AuthD[], int size, std::vector<int> indices) {
    Utils utils;
    this->indices = indices;
    this->pk = pk;
    bn::Ec1 digest_test = utils.compute_digest_pub(I, pk->g1, pk);
    this->digest_I = digest_test;
    this->I = I;
    for (int i = 0; i < size; i++) {
        this->W[i] = W[i];
        this->Q[i] = Q[i];
    }
    this->m = size;
    for (int i = 0; i < m; i++)
        this->AuthD[i] = AuthD[i];
}

VerifyIntersection::~VerifyIntersection() {
}

bool VerifyIntersection::verify_intersection() {
    using namespace ::bn;
    Fp12 e1, e2, e3, e4, e5, e6, e7;
    for (unsigned int i = 0; i < indices.size(); i++) {
        opt_atePairing(e1, *W[indices[i]], digest_I);
        opt_atePairing(e2, pk->g2, AuthD[indices[i]]);
        if (e1 != e2) {
            subsetwitness = false;
            return false;
        }
    }
    subsetwitness = true;
    e3 = 1;
    opt_atePairing(e5, pk->g2, pk->g1);
    for (unsigned int i = 0; i < indices.size(); i++) {
        opt_atePairing(e4, *W[indices[i]], *Q[indices[i]]);
        e3 *= e4;
    }
    if (e3 != e5) {
        completenesswitness = false;
        return false;
    }
    completenesswitness = true;
    return subsetwitness and completenesswitness;
}