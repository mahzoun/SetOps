//
// Created by sauron on 7/12/18.
//

#include "setup.h"

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    NTL::ZZ_p s = sk->sk;
    bn::Ec1 g1 = pk->g1;
    bn::Ec2 g2 = pk->g2;

    for (int i = 0; i < m; i++)
        AuthD[i] = g1;
    for (int i = 0; i < m; i++) {
        for (auto p:D[i]) {
            NTL::ZZ_p x = s + p;
            const mie::Vuint temp(zToString(x));
            AuthD[i] *= temp;
        }
    }
}

void DataStructure::insert(int index, NTL::ZZ_p element, PublicKey *pk, SecretKey *sk){

}
