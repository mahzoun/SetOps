//
// Created by sauron on 7/12/18.
//

#include "source/setup.h"

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    NTL::ZZ_p s = sk->sk;
    for(int i = 0; i < m; i++)
        AuthD[i] = utils.compute_digest(D[i], pk->g1, sk);
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

