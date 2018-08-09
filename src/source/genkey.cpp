//
// Created by sauron on 7/12/18.
//

#include "source/genkey.h"
#define SETS_MAX_SIZE 10000
#define NODEBUG

Key::Key(NTL::ZZ p) {
    NTL::ZZ_p::init(p);
    NTL::ZZ_p temp(0);
    random(temp);
    this->sk = new SecretKey(temp);
    log_info("Secret Key Generated");
    genkey(p);
}

void Key::genkey(NTL::ZZ p){
    create_public_key(sk, p);
    log_info("Public Key Generated");
}

SecretKey* Key::get_secret_key(){
    return sk;
}

void Key::create_public_key(SecretKey* sk, NTL::ZZ p) {
    try{
        PublicKey *key = new PublicKey(p);
        key->setup_bilinear(sk, key->g1, key->g2);
        pk = key;
        }
    catch (std::exception& e) {
        std::cout<<e.what() << '\n';
    }
}

SecretKey::SecretKey() {
    this->sk = 0;
}

SecretKey::SecretKey(NTL::ZZ_p s) {
    this->sk = s;
}

PublicKey* Key::get_public_key() {
    return pk;
}

PublicKey::PublicKey(NTL::ZZ p){
    using namespace bn;
    CurveParam cp = CurveFp254BNb;
    Param::init(cp);
    NTL::ZZ_p::init(p);
    const Point& pt = selectPoint(cp);
    const Ec2 gt2(Fp2(Fp(pt.g2.aa), Fp(pt.g2.ab)), Fp2(Fp(pt.g2.ba), Fp(pt.g2.bb)));
    const Ec1 gt1(pt.g1.a, pt.g1.b);
    g1 = gt1;
    g2 = gt2;
}

void PublicKey::setup_bilinear(SecretKey* sk, bn::Ec1, bn::Ec2){
    using namespace bn;
    using namespace NTL;
    Utils utils;
    ZZ_p temp1;
    ZZ_p temp2;
    ZZ_p s = sk->sk;
    const int q = SETS_MAX_SIZE;
    //TODO optimize following
    for(int i = 0; i < q+1; i++){
        power(temp1, s, i);
        const mie::Vuint temp(utils.zToString(temp1));
        pubs_g1.push_back(g1*temp);
    }
    //g2 pub
    for(int i = 0; i < q+1; i++) {
        power(temp1, s, i);
        const mie::Vuint temp(utils.zToString(temp1));
        pubs_g2.push_back(g2 * temp);
    }

}
