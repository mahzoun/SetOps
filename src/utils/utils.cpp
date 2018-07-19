//
// Created by sauron on 7/17/18.
//

#include "utils.h"

//
//char* zToString(NTL::ZZ_p &z) {
//    std::stringstream buffer;
//    buffer << z;
//
//    char *zzstring = strdup(buffer.str().c_str());
//    return zzstring;
//}

bn::Ec1 Utils::compute_digest_pub(std::set<int> intersection, const bn::Ec1 g1, PublicKey *pk){
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
