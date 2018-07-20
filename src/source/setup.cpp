//
// Created by sauron on 7/12/18.
//

#include "source/setup.h"

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    NTL::ZZ_p s = sk->sk;
    bn::Ec1 g1 = pk->g1;
    bn::Ec2 g2 = pk->g2;
    AuthD[0] = utils.compute_digest_pub(D[0], pk->g1, pk);
    AuthD[1] = utils.compute_digest_pub(D[1], pk->g1, pk);
}

void DataStructure::insert(int index, int element, PublicKey *pk, SecretKey *sk){
    Utils utils;
    //TODO check index :)
    D[index].insert(element);
    //TODO this should be just an update not calculation from scratch
    AuthD[index] = utils.compute_digest_pub(D[index], pk->g1, pk);
    std::cout<<"AuthD[" << index << "]:\t" << AuthD[index] <<"\n";
}

