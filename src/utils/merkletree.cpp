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
    }
}

MerkleTree::~MerkleTree(){
    delete(merkleNode);
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
    while(len > 0){
        depth++;
        if(len%2 == 0) {
            for (int i = 0; i < len/2; i++) {
//                std::cout<< depth <<"\t" << i<<"\t" << merkleNode[depth-1][2*i+1]->hash_ << "\n";
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][2 * i], merkleNode[depth - 1][2 * i + 1]);
                char* temp = utils.concat(merkleNode[depth - 1][2 * i]->hash(), merkleNode[depth - 1][2 * i + 1]->hash());
                merkleNode[depth][i]->hash_ = utils.sha256(temp);
//                std::cout<< len << " \t" << depth <<"\t" << i<<"\t" << merkleNode[depth][i]->hash_ << "\n";
            }
        }
        else{
            for (int i = 0; i < len/2; i++) {
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][i], merkleNode[depth - 1][i + 1]);
                char* temp = utils.concat(merkleNode[depth - 1][2 * i]->hash(), merkleNode[depth - 1][2 * i + 1]->hash());
                merkleNode[depth][i]->hash_ = utils.sha256(temp);
//                std::cout<< len << " \t" << depth <<"\t" << i<<"\t" << merkleNode[depth][i]->hash_ << "\n";
            }
            merkleNode[depth][len/2] = new MerkleNode(nullptr, merkleNode[depth - 1][len - 1]);
            merkleNode[depth][len/2]->hash_ = utils.sha256(merkleNode[depth - 1][len - 1]->hash());
        }
        len/=2;
    }
}
