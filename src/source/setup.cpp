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
    try {
        D[index].insert(element);
        const mie::Vuint temp(zToString(sk->sk));
        AuthD[index] = AuthD[index] * (temp) + AuthD[index] * element;
        std::cout << "AuthD[" << index << "]:\t" << AuthD[index] << "\n";
    }
    catch (std::exception& e) {
        std::cout<<e.what() << '\n';
    }
}

