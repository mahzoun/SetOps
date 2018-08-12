#include <iostream>
#include <chrono>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include "source/setup.h"
#include "server/query.h"
#include "client/verify_intersection.h"
#include "client/verify_tree.h"
#include "client/verify_union.h"
#include "client/verify_subset.h"
#include "client/verify_difference.h"

#define NODEBUG
#define SET_SIZE 10000
#define SETS_NO 4


void test_intersection(int round, int size, int intersection_size, Key *k) {
    using namespace std::chrono;
    high_resolution_clock::time_point t1, t3;
    high_resolution_clock::time_point t2, t4;
    t3 = high_resolution_clock::now();
    //generate sets
    DataStructure *dataStructure = new DataStructure(SETS_NO, k);

    for (int i = 1; i <= intersection_size; i++) {
        NTL::ZZ_p j = NTL::random_ZZ_p();
        for (int set_index = 0; set_index < dataStructure->m; set_index++) {
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    std::cout << size << "\t";
    for (int set_index = 0; set_index < dataStructure->m; set_index++)
        for (int i = 1; i <= size - intersection_size; i++) {
            NTL::ZZ_p j = NTL::random_ZZ_p();
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }

    t4 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t4 - t3).count();
    std::cout << duration << "\t";

    //query intersection
    std::vector<int> v;
    for (int set_index = 0; set_index < dataStructure->m; set_index++)
        v.push_back(set_index);

    t3 = high_resolution_clock::now();
    Intersection *intersection = new Intersection(v, k->get_public_key(), dataStructure);
    intersection->intersect();
    t1 = high_resolution_clock::now();
    intersection->subset_witness();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    std::cout << duration << "\t";

    t1 = high_resolution_clock::now();
    intersection->completeness_witness();
    t2 = high_resolution_clock::now();
    t4 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    std::cout << duration << "\t";
    duration = duration_cast<milliseconds>(t4 - t3).count();
    std::cout << duration << "\n";
//    log_info("Intersection query time:\t%d", duration);
    //verify tree
    //verify intersection
    t1 = high_resolution_clock::now();
    VerifyTree *verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
//    log_info("Tree verification result:\t%x", verifyTree->verifiedtree);
    VerifyIntersection *verifyIntersection = new VerifyIntersection(k->get_public_key(),
                                                                    intersection->I, intersection->W, intersection->Q,
                                                                    dataStructure->AuthD, dataStructure->m, v);
    bool b = verifyIntersection->verify_intersection();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
//    log_info("Intersection verification time:\t%d", duration);
//    log_info("Intersection verification result:\t%x", b);
}

void test_union(int round, int size, int intersection_size, Key *k) {
    using namespace std::chrono;
    high_resolution_clock::time_point t1, t3;
    high_resolution_clock::time_point t2, t4;
    t3 = high_resolution_clock::now();
    //generate sets
    DataStructure *dataStructure = new DataStructure(SETS_NO, k);

    for (int i = 1; i <= intersection_size; i++) {
        NTL::ZZ_p j = NTL::random_ZZ_p();
        for (int set_index = 0; set_index < dataStructure->m; set_index++) {
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    std::cout << size << "\t";
    for (int set_index = 0; set_index < dataStructure->m; set_index++)
        for (int i = 1; i <= size - intersection_size; i++) {
            NTL::ZZ_p j = NTL::random_ZZ_p();
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }

    t4 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t4 - t3).count();
    std::cout << duration << "\t";

    //query intersection
    std::vector<int> v;
    for (int set_index = 0; set_index < dataStructure->m; set_index++)
        v.push_back(set_index);
    t3 = high_resolution_clock::now();
    Union *un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    t1 = high_resolution_clock::now();
    un->membership_witness();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    std::cout << duration << "\t";

    t1 = high_resolution_clock::now();
    un->superset_witness();
    t2 = high_resolution_clock::now();
    t4 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    std::cout << duration << "\t";
    duration = duration_cast<milliseconds>(t4 - t3).count();
    std::cout << duration << "\t";
    t1 = high_resolution_clock::now();
    VerifyTree *verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
    VerifyUnion *verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD,
                                               dataStructure->m, v, un->set_indices);
    verifyUnion->verify_union();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    std::cout << duration << "\n";
    bool b = verifyUnion->membershipwitness and verifyUnion->membershipwitness;
//    log_info("Union verification time:\t%d", duration);
//    log_info("Union verification result:\t%x", b);
}

void test(int size, Key *k) {
    using namespace std::chrono;
    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;

    //generate sets
    DataStructure *dataStructure = new DataStructure(SETS_NO, k);

    for (int i = 1; i <= size / 10; i++) {
        NTL::ZZ_p j = NTL::random_ZZ_p();
        for (int set_index = 0; set_index < dataStructure->m; set_index++) {
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
        }
    }

    for (int set_index = 1; set_index < dataStructure->m; set_index++)
        for (int i = 1; i <= 9 * size / 10; i++) {
            NTL::ZZ_p j = NTL::random_ZZ_p();
            dataStructure->insert(set_index, j, k->get_public_key(), k->get_secret_key());
            dataStructure->insert(0, j, k->get_public_key(), k->get_secret_key());
        }

//    for(int set_index = 0; set_index < dataStructure->m; set_index++)
//        std::cout<<"Size of set " << set_index << " :\t" << dataStructure->D[set_index].size()<<"\n";
//    for (int i = 0; i < dataStructure->m; i++) {
//        std::cout << "AuthD[" << i << "]:\t" << dataStructure->AuthD[i] << "\n";
//    }
    t1 = high_resolution_clock::now();
    //query intersection
    std::vector<int> v;
    for (int set_index = 0; set_index < dataStructure->m; set_index++)
        v.push_back(set_index);

    Intersection *intersection = new Intersection(v, k->get_public_key(), dataStructure);
    intersection->intersect();
    intersection->subset_witness();
    intersection->completeness_witness();
    auto duration = duration_cast<milliseconds>(t2 - t1).count();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Intersection query time:\t%d", duration);
    //verify tree
    VerifyTree *verifyTree = new VerifyTree;
    verifyTree->verifyTree(k->get_public_key(), k->get_secret_key(), dataStructure, v);
    log_info("Tree verification result:\t%x", verifyTree->verifiedtree);
    //verify intersection
    t1 = high_resolution_clock::now();
    VerifyIntersection *verifyIntersection = new VerifyIntersection(k->get_public_key(),
                                                                    intersection->I, intersection->W, intersection->Q,
                                                                    dataStructure->AuthD, dataStructure->m, v);
    bool b = verifyIntersection->verify_intersection();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Intersection verification time:\t%d", duration);
    log_info("Intersection verification result:\t%x", b);

    t1 = high_resolution_clock::now();
    Union *un = new Union(v, k->get_public_key(), dataStructure);
    un->unionSets();
    un->membership_witness();
    un->superset_witness();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Union query time:\t%d", duration);

    t1 = high_resolution_clock::now();
    VerifyUnion *verifyUnion = new VerifyUnion(k->get_public_key(), un->U, un->W1, un->W2, dataStructure->AuthD,
                                               dataStructure->m, v, un->set_indices);
    verifyUnion->verify_union();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Union verification time:\t%d", duration);
    log_info("Union verification result:\t%x", b);

    t1 = high_resolution_clock::now();
    Subset *subset = new Subset(2, 3, k->get_public_key(), dataStructure);
    subset->subset();
    if (subset->answer)
        subset->positiveWitness();
    else
        subset->negativeWitness();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Subset query time:\t%d", duration);

    t1 = high_resolution_clock::now();
    VerifySubset *verifySubset = new VerifySubset(k->get_public_key(), dataStructure, subset->Q, subset->W,
                                                  subset->answer,
                                                  subset->index[0], subset->index[1], subset->y);
    verifySubset->verify_subset();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Subset verification time:\t%d", duration);
    b = verifySubset->verified_subset;
    log_info("Subset verification result:\t%x", b);


    int index[2];
    index[0] = 0;
    index[1] = 1;
    t1 = high_resolution_clock::now();
    Difference *difference = new Difference(index, k->get_public_key(), dataStructure);
    difference->difference();
    difference->witness();
    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Difference query time:\t%d", duration);

    t1 = high_resolution_clock::now();
    VerifyDifference *verifyDifference = new VerifyDifference(k->get_public_key(), dataStructure, difference->D,
                                                              difference->I, difference->W, difference->Wd,
                                                              difference->Q, difference->index);
    verifyDifference->verify_difference();
    duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Difference verification time:\t%d", duration);
    b = verifyDifference->verified_witness;
    log_info("Difference verification result:\t%x", b);
}

int main() {
    using namespace std::chrono;
    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    Key *k = new Key(p);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t2 - t1).count();
    log_info("Key generation time:\t%d", duration);

   // std::cerr<<"size\tsetup\tsubet\tcompleteness\ttotal\n";
   // for (int test_size = 10; test_size <= 10; test_size +=500)
       // for(int i = 0; i < 10; i++)
           // test_intersection(0, test_size, test_size / 10, k);

   std::cerr<<"size\tsetup\tmembership\tsuperset_witness\ttotal\n";
   for (int test_size = 0; test_size <= 1000; test_size +=200)
       for(int i = 0; i < 10; i++)
           test_union(i, test_size, test_size / 10, k);
    // for(int i = 0; i < 1000; i++)
        // test(10, k);
    delete k;
    return 0;
}
