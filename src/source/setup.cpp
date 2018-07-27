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
    this->merkleTree = new MerkleTree(m, this, pk, sk);
    NTL::ZZ_p s = sk->sk;
    for (int i = 0; i < m; i++) {
        AuthD[i] = utils.compute_digest(D[i], pk->g1, sk);
    }
    merkleTree->build(this, pk, sk);
    treeDigest(pk, sk);
    this->depth = merkleTree->depth;
}

void DataStructure::treeDigest(PublicKey *pk, SecretKey *sk) {
    for (int i = 0; i < m; i++) {
        NTL::ZZ_p temp1 = sk->sk + i;
        const mie::Vuint temp(zToString(temp1));
        digest[0][i] = AuthD[i] * temp;
    }
    int len = m;
    int depth = 0;
    while(len > 0){
        depth++;
        if(len%2 == 0) {
            for (int i = 0; i < len/2; i++) {
                digest[depth][i] = calNodeDigest(pk, sk, digest[depth - 1][2 * i], digest[depth - 1][2*i + 1]);
            }
        }
        else{
            for (int i = 0; i < len/2 - 1; i += 2) {
                digest[depth][i] = calNodeDigest(pk, sk, digest[depth - 1][2 * i], digest[depth - 1][2*i + 1]);
            }
            digest[depth][len/2] = calNodeDigest(pk, sk, digest[depth - 1][len - 1], digest[depth - 1][len - 1]);
        }
        len/=2;
    }
}

bn::Ec1 DataStructure::calNodeDigest(PublicKey *pk, SecretKey *sk, bn::Ec1 h1, bn::Ec1 h2) {
    Utils utils;
    bn::Ec1 g1 = pk->g1;
    NTL::ZZ_p s = sk->sk;
    NTL::ZZ_p temp = NTL::conv<NTL::ZZ_p>(1);
    unsigned char *H1, *H2;
    H1 = utils.sha256(utils.Ec1ToString(h1));
    H2 = utils.sha256(utils.Ec1ToString(h2));
    //TODO 250?!
    H1 = (unsigned char *)strndup((char*)H1, 250);
    H2 = (unsigned char *)strndup((char*)H2, 250);
    NTL::ZZ_p x1 = utils.StringToz((char *)H1);
    NTL::ZZ_p x2 = utils.StringToz((char *)H2);
    temp *= (s + x1) * (s + x2);
    const mie::Vuint temp1(zToString(temp));
    bn::Ec1 digest = g1 * temp1;
    return digest;
}

void DataStructure::insert(int index, int element, PublicKey *pk, SecretKey *sk){
    Utils utils;
    try {
        D[index].insert(element);
        NTL::ZZ_p temp1 = sk->sk + element;
        const mie::Vuint temp(zToString(temp1));
        AuthD[index] *= temp;
        AuthD[index] = utils.compute_digest(D[index], pk->g1, sk);
        merkleTree->build(this, pk, sk);
        treeDigest(pk, sk);
        this->depth = merkleTree->depth;
    }
    catch (std::exception& e) {
        std::cout<<e.what() << '\n';
    }
}

