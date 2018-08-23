//
// Created by sauron on 7/12/18.
//

#include "source/setup.h"

#define NODEBUG

DataStructure::DataStructure() {
    this->merkleTree = nullptr;
}

DataStructure::DataStructure(int size, Key *key) {
    debug("Generating datastructure with %d sets", size);
    this->m = size;
    this->merkleTree = new MerkleTree(m, this, key->get_public_key(), key->get_secret_key());
    setup(key->get_public_key(), key->get_secret_key());
}

DataStructure::~DataStructure() {
    delete merkleTree;
}

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    NTL::ZZ_p s = sk->sk;
//    const char *a_str = utils.zToString(sk->a);
//    const mie::Vuint a(a_str);
    for (int i = 0; i < m; i++) {
        AuthD[i] = utils.compute_digest(D[i], pk->g1, sk);
        DEBUGINDEX("Authenticated value for set ", i, AuthD[i]);
//        AuthD2[i] = utils.compute_digest(D[i], pk->g2, sk);
//        AuthD2p[i] = AuthD2[i] * a;
//        DEBUGINDEX("Authenticated value for set ", i, AuthD2[i]);
    }
//    free((char *) a_str);
    merkleTree->build(this, pk, sk);
}

void DataStructure::insert(int index, NTL::ZZ_p element, PublicKey *pk, SecretKey *sk) {
    Utils utils;
    try {
        set_index[element] = index;
        D[index].insert(element);
        NTL::ZZ_p temp1 = sk->sk + element;
        const char *temp1_str = utils.zToString(temp1);
        const mie::Vuint temp(temp1_str);
        free((char *) temp1_str);
        AuthD[index] *= temp;
        DEBUGINDEX("Authenticated value of ", index, AuthD[index]);
        merkleTree->update(this, pk, sk, index);
    }
    catch (std::exception &e) {
        log_err("Error happened in insert to set function");
        std::cerr << e.what() << '\n';
    }
}

