//
// Created by sauron on 7/12/18.
//

#include "setup.h"

void DataStructure::setup(PublicKey *pk, SecretKey *sk) {
    Utils utils;
    NTL::ZZ_p s = sk->sk;
    bn::Ec1 g1 = pk->g1;
    bn::Ec2 g2 = pk->g2;
    AuthD[0] = utils.compute_digest_pub(D[0], pk->g1, pk);
    AuthD[1] = utils.compute_digest_pub(D[1], pk->g1, pk);
}

void DataStructure::insert(int index, int element, PublicKey *pk, SecretKey *sk){
    Utils utils;
    //TODO check index :)
    D[index].insert(element);
    //TODO this should be just an update not calculation from scratch
    AuthD[index] = utils.compute_digest_pub(D[index], pk->g1, pk);
    std::cout<<"AuthD[" << index << "]:\t" << AuthD[index] <<"\n";
}

//TODO move this to utils
bn::Ec1 compute_digest_pub1(std::set<int> intersection, const bn::Ec1 g1, PublicKey *pk){
    using namespace NTL;
    using namespace bn;
    std::vector<double> array(intersection.begin(), intersection.end());
    Ec1 digest = g1*0;
    if(array.size()==0)
        return digest;

    ZZ_pX f,poly;
    poly=ZZ_pX(INIT_MONO,array.size());
    vec_ZZ_p c;
    c.SetLength(array.size());
    for(int i=0;i<array.size();i++)
        c[i] = conv<ZZ_p>(-array[i]);

    BuildFromRoots(poly,c);


    for(int i=0;i<array.size()+1;i++){
        const mie::Vuint temp(zToString(poly[i]));
        digest = digest + pk->pubs_g1[i] * temp;
    }
    return digest;
}
