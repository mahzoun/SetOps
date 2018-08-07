//
// Created by sauron on 7/19/18.
//

#include "client/verify_difference.h"

VerifyDifference::VerifyDifference(PublicKey *pk, DataStructure *dataStructure, std::set<NTL::ZZ_p, ZZ_p_compare> D,
                                   std::set<NTL::ZZ_p, ZZ_p_compare> I, bn::Ec2 *W[], bn::Ec2 *Wd, bn::Ec1 *Q[],
                                   int index[]) {
    Utils utils;
    this->pk = pk;
    this->dataStructure = dataStructure;
    this->D = D;
    this->I = I;
    this->Wd = Wd;
    this->digest_I = utils.compute_digest_pub(I, pk->g1, pk);
    this->digest_D = utils.compute_digest_pub(D, pk->g1, pk);
    for (int i = 0; i < SMALL_QUERY_SIZE; i++) {
        this->index[i] = index[i];
        this->W[i] = W[i];
        this->Q[i] = Q[i];
    }
}

bool VerifyDifference::verify_difference() {
    using namespace ::bn;
    verified_witness = false;
    Fp12 e1, e2, e3, e4, e5, e6, e7;
    opt_atePairing(e1, *Wd, digest_D);
    opt_atePairing(e2, pk->g2, dataStructure->AuthD[index[0]]);
//    PUT(e1);
//    PUT(e2);
    if (e1 != e2) {
        verified_witness = false;
        return false;
    }
    for (int i = 0; i < SMALL_QUERY_SIZE; i++) {
        opt_atePairing(e1, *W[i], digest_I);
        opt_atePairing(e2, pk->g2, dataStructure->AuthD[index[i]]);
//        PUT(e1);
//        PUT(e2);
        if (e1 != e2) {
            verified_witness = false;
            return false;
        }
    }
    e3 = 1;
    opt_atePairing(e5, pk->g2, pk->g1);
    for (int i = 0; i < SMALL_QUERY_SIZE; i++) {
        opt_atePairing(e4, *W[i], *Q[i]);
        e3 *= e4;
    }
//    PUT(e3);
//    PUT(e5);
    if (e3 != e5) {
        verified_witness = false;
        return false;
    }
    verified_witness = true;
//    PUT(verified_witness);
    return verified_witness;
}