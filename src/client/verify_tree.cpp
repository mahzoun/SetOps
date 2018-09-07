//
// Created by sauron on 7/24/18.
//
#include "client/verify_tree.h"

using namespace bn;

VerifyTree::VerifyTree() {
    verifiedtree = false;
}

// Verify the integrity of the sets v
void VerifyTree::verifyTree(PublicKey *pk, SecretKey *sk, DataStructure *dataStructure, std::vector<int> v) {
    Utils utils;
    int len = dataStructure->m;
    int depth = 0;
    NTL::ZZ_p s = sk->sk;
    // for each set in v, calculate the hash value
    for (int i = 0; i < v.size(); i++) {
        NTL::ZZ_p val = s + v[i];
        const char *val_str = utils.zToString(val);
        const mie::Vuint temp(val_str);
        free((char *) val_str);
        bn::Ec1 value_ = dataStructure->AuthD[v[i]] * temp;
        char *ec1str = utils.Ec1ToString(value_);
        unsigned char *hash_ = new unsigned char[256];
        utils.sha256(hash_, ec1str);
        if (strcmp((char *) hash_, (char *) dataStructure->merkleTree->merkleNode[0][v[i]]->hash_) != 0) {
            delete[] hash_;
            return;
        }
        delete[] hash_;
        free(ec1str);
    }
    // rebuild the tree by using the hash values compute in above loop to check their integrity
    // loop on the depth and for each level build the hash values according to the previos level
    while (len > 1) {
        depth++;
        if (len % 2 == 0) {
            for (int i = 0; i < len / 2; i++) {
                char *temp = utils.concat(dataStructure->merkleTree->merkleNode[depth - 1][2 * i]->hash(),
                                          dataStructure->merkleTree->merkleNode[depth - 1][2 * i + 1]->hash());
                unsigned char *res = new unsigned char[256];
                utils.sha256(res, temp);
                if (strcmp((char *) res, (char *) dataStructure->merkleTree->merkleNode[depth][i]->hash_) != 0) {
                    delete[] res;
                    delete[] temp;
                    return;
                }
                delete[] res;
                delete[] temp;
            }
        } else {
            for (int i = 0; i < len / 2; i++) {
                char *temp = utils.concat(dataStructure->merkleTree->merkleNode[depth - 1][2 * i]->hash(),
                                          dataStructure->merkleTree->merkleNode[depth - 1][2 * i + 1]->hash());
                unsigned char *res = new unsigned char[65];
                utils.sha256(res, temp);
                if (strcmp((char *) res, (char *) dataStructure->merkleTree->merkleNode[depth][i]->hash_) != 0) {
                    delete[] res;
                    delete[] temp;
                    return;
                }
                delete[] temp;
                delete[] res;
            }
            char *temp = dataStructure->merkleTree->merkleNode[depth - 1][len - 1]->hash();
            unsigned char *res = new unsigned char[65];
            utils.sha256(res, temp);
            if (strcmp((char *) res, (char *) dataStructure->merkleTree->merkleNode[depth][len / 2]->hash_) != 0) {
                delete[] res;
                delete[] temp;
                return;
            }
            delete[] temp;
            delete[] res;
        }
        len /= 2;
    }
    verifiedtree = true;
}
