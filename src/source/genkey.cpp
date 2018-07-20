//
// Created by sauron on 7/12/18.
//

#include "source/genkey.h"

// TODO: move this to utils
char* zToString(NTL::ZZ_p &z) {
    std::stringstream buffer;
    buffer << z;

    char *zzstring = strdup(buffer.str().c_str());
    return zzstring;
}


void Key::genkey(NTL::ZZ p){
    create_secret_key(sk, p);
    create_public_key(sk, p);
}

void Key::create_secret_key(SecretKey *key, NTL::ZZ p) {
    try {
        NTL::ZZ_p::init(p);
        key = new SecretKey;
        NTL::ZZ_p temp(0);
        random(temp);
        key->sk = temp;
        sk = key;
    }
    catch (std::exception& e) {
        std::cout<<e.what() << '\n';
    }
}

SecretKey* Key::get_secret_key(){
    return sk;
}

void Key::create_public_key(SecretKey* sk, NTL::ZZ p) {
    try{
        PublicKey *key = new PublicKey(sk, p);
        key->setup_bilinear(sk, key->g1, key->g2);
        pk = key;
        }
    catch (std::exception& e) {
        std::cout<<e.what() << '\n';
    }
}

PublicKey* Key::get_public_key() {
    return pk;
}

PublicKey::PublicKey(SecretKey* sk, NTL::ZZ p){
    using namespace bn;
    CurveParam cp = CurveFp254BNb;
    Param::init(cp);
    NTL::ZZ_p::init(p);
//    PUT(Param::r);
//    PUT(Param::p);
//    PUT(Param::t);
    const Point& pt = selectPoint(cp);
    const Ec2 gt2(Fp2(Fp(pt.g2.aa), Fp(pt.g2.ab)), Fp2(Fp(pt.g2.ba), Fp(pt.g2.bb)));
    const Ec1 gt1(pt.g1.a, pt.g1.b);
    g1 = gt1;
    g2 = gt2;
//    PUT(g1);
//    PUT(g2);
}

void PublicKey::setup_bilinear(SecretKey* sk, bn::Ec1, bn::Ec2){
    using namespace bn;
    using namespace NTL;
    ZZ_p temp1;
    ZZ_p temp2;
    ZZ_p s = sk->sk;
    const int q = 1000;
    for(int i = 0; i < q+1; i++){
        power(temp1, s, i);
        const mie::Vuint temp(zToString(temp1));
        pubs_g1.push_back(g1*temp);
    }
    //g2 pub
    for(int i=0;i<q+1;i+=1) {
        power(temp1, s, i);
        const mie::Vuint temp(zToString(temp1));
        pubs_g2.push_back(g2 * temp);
    }

}
