#include <iostream>
#include "source/setup.h"
#include "source/genkey.h"
#include "NTL/ZZ.h"

int main() {
    Key *k = new Key;
    NTL::ZZ p=NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    k->genkey(p);
    DataStructure *dataStructure = new DataStructure;
    dataStructure->setup(k->get_public_key(), k->get_secret_key());
    for(int i = 0; i < dataStructure->m; i++){
        std::cout<< dataStructure->AuthD[i] << "\n";
    }
//    dataStructure->insert(0, NTL::ZZ_p(1), k->get_public_key(), k->get_secret_key());

    return 0;
}