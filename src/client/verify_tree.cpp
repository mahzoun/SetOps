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
    for (unsigned int i = 0; i < v.size(); i++) {
        if (!verifyNode(pk, sk, dataStructure, v)) {
            verifiedtree = false;
            return;
        }
    }
    int len = dataStructure->m;
    int depth = 0;
    NTL::ZZ_p s = sk->sk;
    while (len > 1) {
        depth++;
        if (len % 2 == 0) {
            for (int i = 0; i < len / 2; i++) {
                char *temp = utils.concat(dataStructure->merkleTree->merkleNode[depth - 1][2 * i]->hash(),
                                          dataStructure->merkleTree->merkleNode[depth - 1][2 * i + 1]->hash());
                unsigned char* res = utils.sha256(temp);
                if (strcmp((char*) res, (char *) dataStructure->merkleTree->merkleNode[depth][i]->hash_) != 0)
                    return;
                delete(temp);
                delete(res);
            }
        } else {
            for (int i = 0; i < len / 2; i++) {
                char *temp = utils.concat(dataStructure->merkleTree->merkleNode[depth - 1][2 * i]->hash(),
                                          dataStructure->merkleTree->merkleNode[depth - 1][2 * i + 1]->hash());
                unsigned char* res = utils.sha256(temp);
                if (strcmp((char*) res, (char *) dataStructure->merkleTree->merkleNode[depth][i]->hash_) != 0)
                    return;
                delete(temp);
                delete(res);
            }
            char *temp = dataStructure->merkleTree->merkleNode[depth - 1][len - 1]->hash();
            unsigned char* res = utils.sha256(temp);
            if (strcmp((char*) res, (char *) dataStructure->merkleTree->merkleNode[depth][len / 2]->hash_) != 0)
                return;
            delete(temp);
            delete(res);
        }
        len /= 2;
    }
    verifiedtree = true;
}

bool VerifyTree::verifyNode(PublicKey *pk, SecretKey *sk, DataStructure *dataStructure, std::vector<int> v) {
    Fp12 e1, e2;
    for(unsigned int i = 0; i < v.size(); i++) {
        Ec1 acci = dataStructure->AuthD[v[i]];
        Ec1 dh = dataStructure->merkleTree->merkleNode[0][v[i]]->value_;
        Ec2 gsgi = pk->pubs_g2[1] + pk->g2 * v[i];
        opt_atePairing(e1, pk->g2, dh);
        opt_atePairing(e2, gsgi, acci);
        if(e1 != e2) {
            return false;
        }
    }
    return true;
}
