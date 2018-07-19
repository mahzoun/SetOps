#include <iostream>
#include "NTL/ZZ.h"
#include "source/setup.h"
#include "source/genkey.h"
#include "server/query.h"
#include "client/verify_intersection.h"

int main() {

    Key *k = new Key;
    NTL::ZZ p=NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    k->genkey(p);
    PUT(k->get_secret_key()->sk);

    DataStructure *dataStructure = new DataStructure;
    dataStructure->setup(k->get_public_key(), k->get_secret_key());
    for(int i = 1; i < 5; i++) {
        dataStructure->insert(0, i, k->get_public_key(), k->get_secret_key());
        dataStructure->insert(1, i, k->get_public_key(), k->get_secret_key());
    }
    dataStructure->insert(0, 5, k->get_public_key(), k->get_secret_key());
    dataStructure->insert(1, 6, k->get_public_key(), k->get_secret_key());

    for(int i = 0; i < dataStructure->m; i++){
        std::cout<<"AuthD[" << i <<"]:\t" << dataStructure->AuthD[i] << "\n";
    }

    std::vector<int> v;
    v.push_back(0);
    v.push_back(1);
    Intersection *intersection = new Intersection(v, k->get_public_key(), dataStructure);
    intersection->intersect();
    intersection->subset_witness();
    intersection->completeness_witness();

    VerifyIntersection *verifyIntersection = new VerifyIntersection(k->get_public_key(), *intersection->digest_I, intersection->I, intersection->W1, intersection->W2, intersection->Q1, intersection->Q2, dataStructure->AuthD, dataStructure->m);
    verifyIntersection->verify_intersection();
    std::cout<<"Intersection result is: \t" << 1;
    return 0;
}