#include <iostream>
#include "source/genkey.h"
#include "NTL/ZZ.h"

int main() {
    Key *k = new Key;
    NTL::ZZ p=NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    k->genkey(p);
    std::cout<< "Secret key:\t" << k->get_secret_key()->sk <<"\n";

    return 0;
}