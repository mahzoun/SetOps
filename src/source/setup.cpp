//
// Created by sauron on 7/12/18.
//

#include "setup.h"

bool ZZ_p_compare::operator()(const NTL::ZZ_p &x, const NTL::ZZ_p &y) const {
        return NTL::rep(x) < NTL::rep(y);
}


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
    //TODO check index :)
    //insert element in set
    std::cout<<"Insert\t"<< element << "\t into the " << index << "(th) set\n";
    D[index].insert(element);
    NTL::ZZ_p x = sk->sk + element;
    const mie::Vuint temp(zToString(x));
    AuthD[index] *= temp;
    PUT(AuthD[index]);
}
