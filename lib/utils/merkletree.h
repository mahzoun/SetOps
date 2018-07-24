//
// Created by sauron on 7/21/18.
// Implemented by https://codetrips.com/2016/06/19/implementing-a-merkle-tree-in-c/
//

#ifndef BILINEAR_MERKLETREE_H
#define BILINEAR_MERKLETREE_H

#include <iostream>
#include <memory>
#include <assert.h>
#include <cstdlib>
#include <string.h>
#include <openssl/sha.h>
#include "bn.h"
#include "test_point.hpp"
#include "source/setup.h"
#include "utils/utils.h"
#include <stdlib.h>

#define SETS_MAX_NO 1000

class DataStructure;

class MerkleNode {
public:
    int col, row;
    MerkleNode *left_, *right_;
    unsigned char *hash_;
    bn::Ec1 value_;
    unsigned char *computeHash() const;
    MerkleNode(bn::Ec1 &value){
        value_ = value;
        left_ = nullptr;
        right_ = nullptr;
        hash_ = new unsigned char[SHA256_DIGEST_LENGTH];
    }

    MerkleNode(MerkleNode *left, MerkleNode *right) {
            left_ = left;
            right_ = right;
            hash_ = new unsigned char[SHA256_DIGEST_LENGTH];
    }

//    ~MerkleNode() {
//        if (hash_)
//            delete[](hash_);
//    }

    bool verify();


    char *hash() const {
        return (char*)hash_;
    }

    bool hasChildren() const {
        return left_ || right_;
    }

    const MerkleNode * left() const {
        return left_;
    }
    const MerkleNode * right() const {
        return right_;
    }
};

class MerkleTree{
public:
    static int size;
    MerkleNode *merkleNode[SETS_MAX_NO][SETS_MAX_NO];
//    DataStructure *dataStructure;
//    PublicKey *pk;
//    SecretKey *sk;
    std::vector<bn::Ec1> leafDigest;
    MerkleTree();
    MerkleTree(int, DataStructure*, PublicKey*, SecretKey*);
    ~MerkleTree();
    void build(DataStructure*, PublicKey*, SecretKey*);
    bool verify(DataStructure*, PublicKey*, SecretKey*);

};


#endif //BILINEAR_MERKLETREE_H