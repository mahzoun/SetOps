//
// Created by sauron on 7/21/18.
//
#include "utils/merkletree.h"

size_t basic_hash(const char*, size_t, unsigned char**);
char *hash_str_func(const std::string&);

int MerkleTree::size = SETS_MAX_NO;

MerkleTree::MerkleTree(){
   this->size = SETS_MAX_NO;
}

MerkleTree::MerkleTree(int size){
    this->size = size;
    for(int i = 0; i < size; i++){
        bn::Ec1 x = pk->g1;
        merkleNode[0][i] = new MerkleNode(x);
    }
}

MerkleTree::~MerkleTree(){
    delete(merkleNode);
}

void MerkleTree::build(){
    NTL::ZZ_p s = sk->sk;
    // Build leafs
    for(int i = 0; i < size; i++){
        NTL::ZZ_p val = s + i;
        const mie::Vuint temp(zToString(val));
        merkleNode[0][i]->value_ = dataStructure->AuthD[i] * temp;
    }
    int len = size;
    int depth = 0;
    while(len > 1){
        depth++;
        if(len%2 == 0) {
            for (int i = 0; i < len; i += 2) {
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][i], merkleNode[depth - 1][i + 1]);
                merkleNode[depth][i]->value_ = merkleNode[depth - 1][i]->value_ + merkleNode[depth - 1][i + 1]->value_;
            }
        }
        else{
            for (int i = 0; i < len - 1; i += 2) {
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][i], merkleNode[depth - 1][i + 1]);
                merkleNode[depth][i]->value_ = merkleNode[depth - 1][i]->value_ + merkleNode[depth - 1][i + 1]->value_;
            }
            merkleNode[depth][len-1] = new MerkleNode(nullptr, merkleNode[depth-1][len-1]);
            merkleNode[depth][len-1]->value_ = merkleNode[depth-1][len-1]->value_;
        }
        len/=2;
    }
}

bool MerkleTree::verify(){

}



char *hash_str_func(const std::string& value) {
    unsigned char* buf;
    size_t len = basic_hash(value.c_str(), value.length(), &buf);
    assert(len == SHA256_DIGEST_LENGTH);
    return (char *)buf;
}

size_t basic_hash(const char* value, size_t len, unsigned char** hash_value) {
    *hash_value = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)value, len, *hash_value);

    return SHA256_DIGEST_LENGTH;
}

bool MerkleNode::verify(){
    // If either child is not valid, the entire subtree is invalid too.
    if (left_ && !left_->verify()) {
        return false;
    }
    if (right_ && !right_->verify()) {
        return false;
    }

//    std::unique_ptr<const char> computedHash(hasChildren() ? computeHash() : hash_func(*value_));
//    return memcmp(hash_, computedHash.get(), len()) == 0;
}
