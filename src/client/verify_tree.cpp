//
// Created by sauron on 7/24/18.
//
#include "client/verify_tree.h"
using namespace bn;
void VerifyTree::verifyTree(PublicKey *pk, SecretKey *sk, DataStructure *dataStructure, std::vector<int> v) {
    Utils utils;

    std::cout<<"Verify Leaf Nodes:\t";
    for(int i = 0; i < v.size(); i++){
        if(!verifyNode(pk, sk, dataStructure, v)){
            std::cout<<"Failed!\n";
            return;
        }
    }
    std::cout<<"Passed!\n";

    std::cout<<"Verify Path Nodes:\t";
    int len = dataStructure->m;
    int depth = 0;
    MerkleTree *tmp = new MerkleTree(dataStructure->m, dataStructure, pk, sk);
    NTL::ZZ_p s = sk->sk;
    for(int i = 0; i < dataStructure->m; i++){
        NTL::ZZ_p val = s + i;
        const mie::Vuint temp(zToString(val));
        tmp->merkleNode[0][i]->value_ = dataStructure->AuthD[i] * temp;
        tmp->merkleNode[0][i]->hash_ = utils.sha256(utils.Ec1ToString(tmp->merkleNode[0][i]->value_));
    }
    while(len > 0){
        depth++;
        if(len%2 == 0) {
            for (int i = 0; i < len/2; i++) {
                tmp->merkleNode[depth][i] = new MerkleNode(tmp->merkleNode[depth - 1][2 * i], tmp->merkleNode[depth - 1][2 * i + 1]);
                char* temp = utils.concat(tmp->merkleNode[depth - 1][2 * i]->hash(), tmp->merkleNode[depth - 1][2 * i + 1]->hash());
                tmp->merkleNode[depth][i]->hash_ = utils.sha256(temp);
                if(strcmp((char*)tmp->merkleNode[depth][i]->hash_, (char*)dataStructure->merkleTree->merkleNode[depth][i]->hash_) != 0){
                    std::cout << "Failed!\n";
                    return;
                }

            }
        }
        else{
            for (int i = 0; i < len/2 - 1; i += 2) {
                tmp->merkleNode[depth][i] = new MerkleNode(tmp->merkleNode[depth - 1][i], tmp->merkleNode[depth - 1][i + 1]);
                char* temp = utils.concat(tmp->merkleNode[depth - 1][2 * i]->hash(), tmp->merkleNode[depth - 1][2 * i + 1]->hash());
                tmp->merkleNode[depth][i]->hash_ = utils.sha256(temp);
                if(strcmp((char*)tmp->merkleNode[depth][i]->hash_, (char*)dataStructure->merkleTree->merkleNode[depth][i]->hash_)!= 0){
                    std::cout << "Failed!\n";
                    return;
                }
            }
            tmp->merkleNode[depth][len/2] = new MerkleNode(nullptr, tmp->merkleNode[depth - 1][len - 1]);
            tmp->merkleNode[depth][len/2]->hash_ = utils.sha256(tmp->merkleNode[depth - 1][len - 1]->hash());
            if(strcmp((char*)tmp->merkleNode[depth][len/2]->hash_, (char*)dataStructure->merkleTree->merkleNode[depth][len/2]->hash_) != 0 ){
                std::cout << "Failed!\n";
                return;
            }


        }
        len/=2;
    }
    std::cout<<"Passed!\n";
//    for(int i = 2; i < dataStructure->depth; i++){
//        Fp12 e1, e2;
//        int child = v[i] >> i;
//        opt_atePairing(e1, pk->g2, dataStructure->digest[i][child]);
//        unsigned char * H1 = utils.sha256(utils.Ec1ToString(dataStructure->gamma[i][child][child & 1]));
//        Ec1 other_child = dataStructure->digest[i-1][child * 2 + (not child & 1)];
//        unsigned char * H2 = utils.sha256(utils.Ec1ToString(other_child));
//        //TODO 250?!
//        H1 = (unsigned char *)strndup((char*)H1, 250);
//        H2 = (unsigned char *)strndup((char*)H2, 250);
//        NTL::ZZ_p x1 = utils.StringToz((char *)H1);
//        NTL::ZZ_p x2 = utils.StringToz((char *)H2);
//        const mie::Vuint temp1((char *)H2);
//        other_child = pk->pubs_g1[1] + pk->g1 * temp1;
//        Ec1 g1h = other_child;
//        const mie::Vuint temp((char *)H1);
//        Ec2 g2h = pk->g2*0 * temp;
//        opt_atePairing(e2, g2h, g1h);
//        if( e1 != e2){
//            std::cout<<"Failed!\n";
//            return;
//        }
//    }

}

bool VerifyTree::verifyNode(PublicKey *pk, SecretKey *sk, DataStructure *dataStructure, std::vector<int> v) {
    Fp12 e1, e2;
    for(int i = 0; i < v.size(); i++) {
        Ec1 acci = dataStructure->AuthD[i];
        Ec1 dh = dataStructure->digest[0][v[i]];
        Ec2 gsgi = pk->pubs_g2[1] + pk->g2 * v[i];
        opt_atePairing(e1, pk->g2, dh);
        opt_atePairing(e2, gsgi, acci);
        if( e1 != e2){
            return false;
        }
    }
}
