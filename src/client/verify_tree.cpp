//
// Created by sauron on 7/24/18.
//
#include "client/verify_tree.h"
using namespace bn;
VerifyTree::VerifyTree() {
    verifiedtree = false;
}

void VerifyTree::verifyTree(PublicKey *pk, SecretKey *sk, DataStructure *dataStructure, std::vector<int> v) {
    Utils utils;
    for(int i = 0; i < v.size(); i++){
//        std::cout<<"fuck at \t" << i << "\n";
        if(!verifyNode(pk, sk, dataStructure, v)){
            verifiedtree = false;
            return;
        }
    }
    int len = dataStructure->m;
    int depth = 0;
    MerkleTree *tmp = new MerkleTree(dataStructure->m, dataStructure, pk, sk);
    NTL::ZZ_p s = sk->sk;
    for(int i = 0; i < dataStructure->m; i++){
        NTL::ZZ_p val = s + i;
        const mie::Vuint temp(utils.zToString(val));
        tmp->merkleNode[0][i]->value_ = dataStructure->AuthD[i] * temp;
        tmp->merkleNode[0][i]->hash_ = utils.sha256(utils.Ec1ToString(tmp->merkleNode[0][i]->value_));
//        std::cout<< len << "\t" << i << "\t" << depth << "\t" << tmp->merkleNode[depth][i]->hash() << "\n";
    }
    while(len > 0){
        depth++;
        if(len%2 == 0) {
            for (int i = 0; i < len/2; i++) {
                tmp->merkleNode[depth][i] = new MerkleNode(tmp->merkleNode[depth - 1][2 * i], tmp->merkleNode[depth - 1][2 * i + 1]);
                char* temp = utils.concat(tmp->merkleNode[depth - 1][2 * i]->hash(), tmp->merkleNode[depth - 1][2 * i + 1]->hash());
                tmp->merkleNode[depth][i]->hash_ = utils.sha256(temp);
//                std::cout<< len << "\t" << i << "\t" << depth << "\t" << tmp->merkleNode[depth][i]->hash() << "\n";
                if(strcmp((char*)tmp->merkleNode[depth][i]->hash_, (char*)dataStructure->merkleTree->merkleNode[depth][i]->hash_) != 0){
                    return;
                }

            }
        }
        else{
            for (int i = 0; i < len/2; i++) {
                tmp->merkleNode[depth][i] = new MerkleNode(tmp->merkleNode[depth - 1][i], tmp->merkleNode[depth - 1][i + 1]);
                char* temp = utils.concat(tmp->merkleNode[depth - 1][2 * i]->hash(), tmp->merkleNode[depth - 1][2 * i + 1]->hash());
                tmp->merkleNode[depth][i]->hash_ = utils.sha256(temp);
//                std::cout<< len << "\t" << i << "\t" << depth << "\t" << tmp->merkleNode[depth][i]->hash() << "\n";
                if(strcmp((char*)tmp->merkleNode[depth][i]->hash_, (char*)dataStructure->merkleTree->merkleNode[depth][i]->hash_)!= 0){
                    return;
                }
            }
            tmp->merkleNode[depth][len/2] = new MerkleNode(nullptr, tmp->merkleNode[depth - 1][len - 1]);
            tmp->merkleNode[depth][len/2]->hash_ = utils.sha256(tmp->merkleNode[depth - 1][len - 1]->hash());
            if(strcmp((char*)tmp->merkleNode[depth][len/2]->hash_, (char*)dataStructure->merkleTree->merkleNode[depth][len/2]->hash_) != 0 ){
                return;
            }


        }
        len/=2;
    }
    verifiedtree = true;
}

bool VerifyTree::verifyNode(PublicKey *pk, SecretKey *sk, DataStructure *dataStructure, std::vector<int> v) {
    Fp12 e1, e2;
    for(int i = 0; i < v.size(); i++) {
        Ec1 acci = dataStructure->AuthD[v[i]];
        Ec1 dh = dataStructure->digest[0][v[i]];
        Ec2 gsgi = pk->pubs_g2[1] + pk->g2 * v[i];
//        PUT(i);
//        PUT(acci);
//        PUT(dh);
//        PUT(gsgi);
        opt_atePairing(e1, pk->g2, dh);
        opt_atePairing(e2, gsgi, acci);
//        PUT(e1);
//        PUT(e2);
        if(e1 != e2) {
            return false;
        }
    }
    return true;
}
