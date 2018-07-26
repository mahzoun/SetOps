#include <iostream>
#include <chrono>
#include <cstdlib>
#include <NTL/ZZ.h>
#include "source/setup.h"
#include "source/genkey.h"
#include "server/query.h"
#include "client/verify_intersection.h"
#include "client/verify_tree.h"
#define SET_SIZE 10000
#define SETS_NO 8

void test(int size, Key *k){
    std::cout<< size << "\t";
    using namespace std::chrono;
    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;

    //generate sets
    DataStructure *dataStructure = new DataStructure(SETS_NO);
    dataStructure->setup(k->get_public_key(), k->get_secret_key());
    for(int i = 1; i <= size/10; i++) {
        int j = rand();
        for(int set_index = 0; set_index < dataStructure->m; set_index++) {
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    for(int set_index = 0; set_index < dataStructure->m; set_index++)
        for(int i = 1; i <= 9*size/10; i++) {
            int j = rand();
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }

//    for(int set_index = 0; set_index < dataStructure->m; set_index++)
//        std::cout<<"Size of set " << set_index << " :\t" << dataStructure->D[set_index].size()<<"\n";
//    for(int i = 0; i < dataStructure->m; i++){
//        std::cout<<"AuthD[" << i <<"]:\t" << dataStructure->AuthD[i] << "\n";
//    }
    t1 = high_resolution_clock::now();
    //query intersection
    std::vector<int> v;
    for(int set_index = 0; set_index < dataStructure->m; set_index++)
        v.push_back(set_index);

    Intersection *intersection = new Intersection(v, k->get_public_key(), dataStructure);
    intersection->intersect();
    intersection->subset_witness();
    intersection->completeness_witness();
    auto duration = duration_cast<milliseconds>( t2 - t1 ).count();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>( t2 - t1 ).count();
    std::cout <<"Query Time:\t" << duration << "\n";
    //verify tree
    VerifyTree *verifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);

    //verify intersection
    t1 = high_resolution_clock::now();
    VerifyIntersection *verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W, intersection->Q, dataStructure->AuthD, dataStructure->m);
    bool b = verifyIntersection->verify_intersection();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>( t2 - t1 ).count();
    std::cout << "Verify Time:\t" << duration << "\n";
    std::cout << "Intersection result is: \t" << b << "\n";

}

int main() {
    using namespace std::chrono;
    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    //generate keys
    Key *k = new Key;
    NTL::ZZ p=NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    k->genkey(p);
//    PUT(k->get_secret_key()->sk);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>( t2 - t1 ).count();
    std::cout << "Key generation time:\t" << duration << "\n";
    
//    for(int test_size = 10; test_size <= SET_SIZE*100 ; test_size *= 2)
    test(16, k);

    return 0;
}