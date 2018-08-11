//
// Created by sauron on 7/21/18.
//
#include "utils/merkletree.h"

//int MerkleTree::size = SETS_MAX_NO;

MerkleTree::MerkleTree(){
   this->size = SETS_MAX_NO;
}

MerkleTree::MerkleTree(int size, DataStructure *dataStructure, PublicKey *pk, SecretKey *sk){
    this->size = size;
    for(int i = 0; i < size; i++){
        bn::Ec1 x = pk->g1;
        merkleNode[0][i] = new MerkleNode(x);
        debug("merke node %d %d created", 0, i);
    }
    debug("MerkleTree Created successfully with %d leafs", size);
}

MerkleTree::~MerkleTree(){
    for(int i = 0; i < size; i++)
        for(int j = 0; j < size; j++)
            if(merkleNode[i][j]){
                delete(merkleNode[i][j]);
            }
}

void MerkleTree::build(DataStructure *dataStructure, PublicKey *pk, SecretKey *sk){
    Utils utils;
    NTL::ZZ_p s = sk->sk;
    this->size = dataStructure->m;
    for(int i = 0; i < size; i++){
        NTL::ZZ_p val = s + i;
        const mie::Vuint temp(utils.zToString(val));
        merkleNode[0][i]->value_ = dataStructure->AuthD[i] * temp;
        merkleNode[0][i]->hash_ = utils.sha256(utils.Ec1ToString(merkleNode[0][i]->value_));
    }
    int len = size;
    depth = 0;
    while(len > 1){
        depth++;
        debug("Initializing depth:\t%d with the len of:\t%d", depth, len);
        if(len%2 == 0) {
            for (int i = 0; i < len/2; i++) {
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][2 * i], merkleNode[depth - 1][2 * i + 1]);
                debug("merke node %d %d created", depth, i);
                char* temp = utils.concat(merkleNode[depth - 1][2 * i]->hash(), merkleNode[depth - 1][2 * i + 1]->hash());
                merkleNode[depth][i]->hash_ = utils.sha256(temp);
                delete(temp);
                debug("Hash value of node %d in depth %d is %s", i, depth, merkleNode[depth][i]->hash_);
            }
        }
        else{
            for (int i = 0; i < len/2; i++) {
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][i], merkleNode[depth - 1][i + 1]);
                debug("merke node %d %d created", depth, i);
                char* temp = utils.concat(merkleNode[depth - 1][2 * i]->hash(), merkleNode[depth - 1][2 * i + 1]->hash());
                delete(temp);
                merkleNode[depth][i]->hash_ = utils.sha256(temp);
                debug("Hash value of node %d in depth %d is %s", i, depth, merkleNode[depth][i]->hash_);
            }
            merkleNode[depth][len/2] = new MerkleNode(nullptr, merkleNode[depth - 1][len - 1]);
            debug("merke node %d %d created", depth, len/2);
            merkleNode[depth][len/2]->hash_ = utils.sha256(merkleNode[depth - 1][len - 1]->hash());
            debug("Hash value of node %d in depth %d is %s", len, depth, merkleNode[depth][len/2]->hash_);
        }
        len/=2;
    }
}

void MerkleTree::update(DataStructure *dataStructure, PublicKey *pk, SecretKey *sk, int index) {
    Utils utils;
    NTL::ZZ_p s = sk->sk;
    this->size = dataStructure->m;
    NTL::ZZ_p val = s + index;
    const mie::Vuint temp(utils.zToString(val));
    merkleNode[0][index]->value_ = dataStructure->AuthD[index] * temp;
    merkleNode[0][index]->hash_ = utils.sha256(utils.Ec1ToString(merkleNode[0][index]->value_));
    debug("Hash value of leaf %d in depth %d is updated to %s", index, depth, merkleNode[0][index]->hash_);
    int len = size;
    depth = 0;
    while (len > 1) {
        depth++;
        index /= 2;
        char *temp = utils.concat(merkleNode[depth - 1][2 * index]->hash(),
                                  merkleNode[depth - 1][2 * index + 1]->hash());
        merkleNode[depth][index]->hash_ = utils.sha256(temp);
        delete(temp);
        debug("Hash value of node %d in depth %d is %s", index, depth, merkleNode[depth][index]->hash_);
        len /= 2;
    }
}
