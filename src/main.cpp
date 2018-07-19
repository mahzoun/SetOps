#include <iostream>
#include "NTL/ZZ.h"
#include "source/setup.h"
#include "source/genkey.h"
#include "server/query.h"

int main() {
    Key *k = new Key;
    NTL::ZZ p=NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    k->genkey(p);
    DataStructure *dataStructure = new DataStructure;
    dataStructure->setup(k->get_public_key(), k->get_secret_key());
    for(int i = 0; i < 5; i++) {
        dataStructure->insert(0, i, k->get_public_key(), k->get_secret_key());
        dataStructure->insert(1, i, k->get_public_key(), k->get_secret_key());
    }

    dataStructure->insert(0, 5, k->get_public_key(), k->get_secret_key());
    dataStructure->insert(1, 6, k->get_public_key(), k->get_secret_key());

    for(int i = 0; i < dataStructure->m; i++){
        PUT(dataStructure->AuthD[i])
    }

    std::vector<int> v;
    v.push_back(0);
    v.push_back(1);
    Intersection *intersection = new Intersection(v, k->get_public_key(), dataStructure);
    intersection->intersect();
    intersection->subset_witness();
    return 0;
}