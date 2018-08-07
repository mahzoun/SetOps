#include <iostream>
#include <chrono>
#include <cstdlib>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include "source/setup.h"
#include "source/genkey.h"
#include "server/query.h"
#include "client/verify_intersection.h"
#include "client/verify_tree.h"
#include "client/verify_union.h"
#include "client/verify_subset.h"
#define SET_SIZE 10000
#define SETS_NO 10

void test(int size, Key *k){
    using namespace std::chrono;
    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;

    //generate sets
    DataStructure *dataStructure = new DataStructure(SETS_NO, k);

    for(int i = 1; i <= size/10; i++) {
        NTL::ZZ_p j = NTL::random_ZZ_p();
        for(int set_index = 0; set_index < dataStructure->m; set_index++) {
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    for(int set_index = 1; set_index < dataStructure->m; set_index++)
        for(int i = 1; i <= 9*size/10; i++) {
            NTL::ZZ_p j = NTL::random_ZZ_p();
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
            dataStructure->insert(0, j, k->get_public_key(), k->get_secret_key());
        }

//    for(int set_index = 0; set_index < dataStructure->m; set_index++)
//        std::cout<<"Size of set " << set_index << " :\t" << dataStructure->D[set_index].size()<<"\n";
    for(int i = 0; i < dataStructure->m; i++){
        std::cout<<"AuthD[" << i <<"]:\t" << dataStructure->AuthD[i] << "\n";
    }
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
    VerifyTree *verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);

    //verify intersection
    t1 = high_resolution_clock::now();
    VerifyIntersection *verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W, intersection->Q, dataStructure->AuthD, dataStructure->m, v);
    bool b = verifyIntersection->verify_intersection();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>( t2 - t1 ).count();
    std::cout << "Verify Time:\t" << duration << "\n";
    std::cout << "Intersection result is: \t" << b << "\n";

    Union *un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    un->membership_witness();
    un->superset_witness();

    VerifyUnion *verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD, dataStructure->m, v, un->set_indices);
    verifyUnion->verify_union();
    std::cout << "Union result is: \t" << (verifyUnion->membershipwitness and verifyUnion->membershipwitness) << "\n";

    Subset *subset = new Subset(2, 3, k->get_public_key(), dataStructure);
    subset->subset();
    if(subset->answer)
        subset->positiveWitness();
    else
        subset->negativeWitness();

    VerifySubset *verifySubset = new VerifySubset(k->get_public_key(), dataStructure, subset->Q, subset->W, subset->answer,
            subset->index[0], subset->index[1], subset->y);
    verifySubset->verify_subset();
    std::cout << "Subset result is: \t" << verifySubset->verified_subset << "\n";
    int index[2];
    index[0] = 0;
    index[1] = 1;
    Difference *difference = new Difference(index, k->get_public_key(), dataStructure);
    difference->difference();
    difference->witness();
}

int main() {
    using namespace std::chrono;
    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    //generate keys
    NTL::ZZ p=NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    Key *k = new Key(p);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>( t2 - t1 ).count();
    std::cout << "Key generation time:\t" << duration << "\n";
    
//    for(int test_size = 10; test_size <= SET_SIZE*100 ; test_size *= 2)
    test(10, k);

    return 0;
}