//
// Created by sauron on 7/19/18.
//

#include "client/verify_intersection.h"

int VerifyIntersection::m = 2;

VerifyIntersection::VerifyIntersection(PublicKey *pk, bn::Ec1 digest_I, std::set<int> I, bn::Ec2 *W[], bn::Ec1 *Q[], bn::Ec1 AuthD[], int size){
    Utils utils;
    this->pk = pk;
    bn::Ec1 digest_test = utils.compute_digest_pub(I, pk->g1, pk);
    this->digest_I = digest_test;
    this->I = I;
    for(int i = 0; i < size; i++) {
        this->W[i] = W[i];
        this->Q[i] = Q[i];
    }
    this->m = size;
    for(int i = 0; i < m; i++)
        this->AuthD[i] = AuthD[i];
}

bool VerifyIntersection::verify_intersection() {
    using namespace::bn;
    Fp12 e1, e2, e3, e4, e5, e6, e7;
    std::cout<<"Checking subset witnesses:\t";
    for(int i = 0; i < m; i++) {
        opt_atePairing(e1, *W[i], digest_I);
        opt_atePairing(e2, pk->g2, AuthD[i]);
        if( e1 != e2){
            std::cout<<"Failed!\n";
            return false;
        }
    }
    std::cout<<"Passed!\n";
    std::cout<<"Checking completeness witnesses:\t";
    e3 = 1;
    opt_atePairing(e5, pk->g2, pk->g1);
    for(int i = 0; i < m; i++) {
        opt_atePairing(e4, *W[i], *Q[i]);
        e3 *= e4;
    }
    if( e3 != e5){
        std::cout<<"Failed!\n";
        return false;
    }
    std::cout<<"Passed!\n";
    return true;
}