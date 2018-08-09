//
// Created by sauron on 7/12/18.
//

#include "source/setup.h"
#define NODEBUG

DataStructure::DataStructure(int size, Key *key){
    debug("Generating datastructure with %d sets", size);
    this->m = size;
    setup(key->get_public_key(), key->get_secret_key());
}

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    this->merkleTree = new MerkleTree(m, this, pk, sk);
    NTL::ZZ_p s = sk->sk;
    for (int i = 0; i < m; i++) {
        AuthD[i] = utils.compute_digest(D[i], pk->g1, sk);
        DEBUGINDEX("Authenticated value for set ", i , AuthD[i]);
    }
    merkleTree->build(this, pk, sk);
    treeDigest(pk, sk);
    this->depth = merkleTree->depth;
}

void DataStructure::treeDigest(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    for (int i = 0; i < m; i++) {
        NTL::ZZ_p temp1 = sk->sk + i;
        const mie::Vuint temp(utils.zToString(temp1));
        digest[0][i] = AuthD[i] * temp;
        DEBUG2INDEX("Tree digest of ", i, 0, digest[0][i]);
    }
    int len = m;
    int depth = 0;
    while (len > 1) {
        depth++;
        if (len % 2 == 0) {
            for (int i = 0; i < len / 2; i++) {
                digest[depth][i] = calNodeDigest(pk, sk, digest[depth - 1][2 * i], digest[depth - 1][2 * i + 1]);
                DEBUG2INDEX("Tree digest of ", i, depth, digest[depth][i]);
            }
        } else {
            for (int i = 0; i < len / 2; i++) {
                digest[depth][i] = calNodeDigest(pk, sk, digest[depth - 1][2 * i], digest[depth - 1][2 * i + 1]);
                DEBUG2INDEX("Tree digest of ", i, depth, digest[depth][i]);
            }
            digest[depth][len / 2] = calNodeDigest(pk, sk, digest[depth - 1][len - 1], digest[depth - 1][len - 1]);
            DEBUG2INDEX("Tree digest of ", len / 2, depth, digest[depth][len / 2]);
        }
        len /= 2;
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
    const mie::Vuint temp1(utils.zToString(temp));
    bn::Ec1 digest = g1 * temp1;
    return digest;
}

void DataStructure::insert(int index, NTL::ZZ_p element, PublicKey *pk, SecretKey *sk){
    Utils utils;
    try {
        D[index].insert(element);
        debug("Insert %s in the set %d", utils.zToString(element), index);
        NTL::ZZ_p temp1 = sk->sk + element;
        const mie::Vuint temp(utils.zToString(temp1));
        AuthD[index] *= temp;
        AuthD[index] = utils.compute_digest(D[index], pk->g1, sk);
        DEBUGINDEX("Authenticated value of ", index, AuthD[index]);
        merkleTree->update(this, pk, sk, index);
        treeDigest(pk, sk);
        this->depth = merkleTree->depth;
    }
    catch (std::exception& e) {
        log_err("Error happened in insert to set function");
        std::cerr<<e.what() << '\n';
    }
}

