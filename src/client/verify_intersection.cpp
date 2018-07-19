//
// Created by sauron on 7/19/18.
//

#include "verify_intersection.h"

VerifyIntersection::VerifyIntersection(PublicKey *pk, bn::Ec1 digest_I, std::set<int> I, bn::Ec2 *W1, bn::Ec2 *W2, bn::Ec1 *Q1, bn::Ec1 *Q2, bn::Ec1 AuthD[], int size){
    this->pk = pk;
    this->digest_I = digest_I;
    this->I = I;
    this->W1 = W1;
    this->W2 = W2;
    this->Q1 = Q1;
    this->Q2 = Q2;
//    this->m = size;
    for(int i = 0; i < m; i++)
        this->AuthD[i] = AuthD[i];

}

bool VerifyIntersection::verify_intersection() {
    using namespace::bn;
    Fp12 e1, e2,e3,e4,e5,e6,e7;
    opt_atePairing(e1, *W1, digest_I);
    opt_atePairing(e2, pk->g2, AuthD[0]);

    opt_atePairing(e3, *W2, digest_I);
    opt_atePairing(e4, pk->g2, AuthD[1]);

    opt_atePairing(e5, *W1, *Q1);
    opt_atePairing(e6, *W2, *Q2);
    opt_atePairing(e7, pk->g2, pk->g1);

    return e1 == e2 && e3 == e4 && e5*e6 == e7;
}