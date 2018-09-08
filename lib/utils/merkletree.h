//
// Created by sauron on 7/21/18.
// Implemented by https://codetrips.com/2016/06/19/implementing-a-merkle-tree-in-c/
//

#ifndef BILINEAR_MERKLETREE_H
#define BILINEAR_MERKLETREE_H
#define NODEBUG

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

#define SETS_MAX_NO 2000

class DataStructure;

/*
 * A node for tree contains the hash_ and child pointers
 * value_ used to store the values for leafs and its null for internal nodes
 */
class MerkleNode {
public:
    MerkleNode *left_, *right_;
    unsigned char *hash_;
    bn::Ec1 value_;

    MerkleNode(bn::Ec1 &value) {
        value_ = value;
        left_ = nullptr;
        right_ = nullptr;
        hash_ = new unsigned char[256];
    }

    MerkleNode(MerkleNode *left, MerkleNode *right) {
        left_ = left;
        right_ = right;
        hash_ = new unsigned char[256];
    }

    ~MerkleNode() {
        if (hash_)
            delete[] hash_;
    }

    char *hash() const {
        return (char *) hash_;
    }
};

/*
 * Store the pointer to each node in a 2D array for easier traversal
 * tree[i][j] is the father of tree[i-1][2j] and tree[i-1][2j+1]
 */
class MerkleTree {
public:
    int size;
    int depth;
    MerkleNode *merkleNode[SETS_MAX_NO][SETS_MAX_NO];

    MerkleTree();

    MerkleTree(int, PublicKey *);

    ~MerkleTree();

    void build(DataStructure *, SecretKey *);

    void update(DataStructure *, int);
};


#endif //BILINEAR_MERKLETREE_H
