//
// Created by sauron on 7/21/18.
//
#include "utils/merkletree.h"

unsigned char* sha256(char *);
char* concat(const char*, const char*);

int MerkleTree::size = SETS_MAX_NO;

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
    for(int i = 0; i < size; i++){
        NTL::ZZ_p val = s + i;
        const mie::Vuint temp(zToString(val));
        merkleNode[0][i]->value_ = dataStructure->AuthD[i] * temp;
        merkleNode[0][i]->hash_ = sha256(utils.Ec1ToString(merkleNode[0][i]->value_));
    }
    int len = size;
    int depth = 0;
    while(len > 0){
        depth++;
        if(len%2 == 0) {
            for (int i = 0; i < len/2; i++) {
                std::cout << i << "\t" << len << "\t" << depth << "\n";
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][2 * i], merkleNode[depth - 1][2 * i + 1]);
                char* temp = concat(merkleNode[depth - 1][2 * i]->hash(), merkleNode[depth - 1][2 * i + 1]->hash());
                merkleNode[depth][i]->hash_ = sha256(temp);
            }
        }
        else{
            for (int i = 0; i < len/2 - 1; i += 2) {
                merkleNode[depth][i] = new MerkleNode(merkleNode[depth - 1][i], merkleNode[depth - 1][i + 1]);
                char* temp = concat(merkleNode[depth - 1][2 * i]->hash(), merkleNode[depth - 1][2 * i + 1]->hash());
                merkleNode[depth][i]->hash_ = sha256(temp);
            }
            merkleNode[depth][len/2] = new MerkleNode(nullptr, merkleNode[depth - 1][len - 1]);
            merkleNode[depth][len/2]->hash_ = sha256(merkleNode[depth - 1][len - 1]->hash());
        }
        len/=2;
    }
}

bool MerkleTree::verify(DataStructure *dataStructure, PublicKey* pk, SecretKey *sk){
NTL::ZZ_p s = sk->sk;
    // check leafs
    for(int i = 0; i < size; i++){
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


char* concat(const char *s1, const char *s2)
{
    char *result = new char[strlen(s1) + strlen(s2) + 1]; // +1 for the null-terminator
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

unsigned char* sha256(char *string)
{
    unsigned char *hash = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    return hash;
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
