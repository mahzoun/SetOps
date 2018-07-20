//
// Created by sauron on 7/12/18.
//

#include "source/setup.h"

int DataStructure::m = 2;

DataStructure::DataStructure() {
    m = 2;
}

DataStructure::DataStructure(int size){
    m = size;
}

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    NTL::ZZ_p s = sk->sk;
    for (int i = 0; i < m; i++) {
        AuthD[i] = utils.compute_digest(D[i], pk->g1, sk);
//        std::cout << "AuthD[" << i << "]:\t" << AuthD[i] << "\n";
    }
}
void DataStructure::insert(int index, int element, PublicKey *pk, SecretKey *sk){
    Utils utils;
    try {
        D[index].insert(element);
        NTL::ZZ_p temp1 = sk->sk + element;
        const mie::Vuint temp(zToString(temp1));
        AuthD[index] *= temp;
//        std::cout << "AuthD[" << index << "]:\t" << AuthD[index] << "\n";
//        AuthD[index] = utils.compute_digest(D[index], pk->g1, sk);
//        std::cout << "AuthD[" << index << "]:\t" << AuthD[index] << "\n";
    }
    catch (std::exception& e) {
        std::cout<<e.what() << '\n';
    }
}

