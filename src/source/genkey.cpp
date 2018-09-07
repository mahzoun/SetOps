//
// Created by sauron on 7/12/18.
//

#include "source/genkey.h"

#define SETS_MAX_SIZE 10000
#define MAX_SIZE_LG 20
#define NODEBUG

Key::Key() {
    NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
    NTL::ZZ_p::init(p);
    NTL::ZZ_p temp(0);
    random(temp);
    NTL::ZZ_p temp1(0);
    random(temp1);
    this->sk = new SecretKey(temp, temp1);
    log_info("Secret Key Generated");
    genkey(p);
}

Key::Key(NTL::ZZ p) {
    NTL::ZZ_p::init(p);
    NTL::ZZ_p temp(0);
    random(temp);
    NTL::ZZ_p temp1(0);
    random(temp1);
    this->sk = new SecretKey(temp, temp1);
    log_info("Secret Key Generated");
    genkey(p);
}

void Key::genkey(NTL::ZZ p) {
    create_public_key(sk, p);
    log_info("Public Key Generated");
}

Key::~Key() {
    if (sk)
        delete (sk);
    if (pk)
        delete (pk);
}

SecretKey *Key::get_secret_key() {
    return sk;
}

void Key::create_public_key(SecretKey *sk, NTL::ZZ p) {
    try {
        PublicKey *key = new PublicKey(p);
        key->setup_bilinear(sk, key->g1, key->g2);
        pk = key;
    }
    catch (std::exception &e) {
        std::cout << e.what() << '\n';
    }
}

SecretKey::SecretKey() {
    this->sk = 0;
}

SecretKey::SecretKey(NTL::ZZ_p s, NTL::ZZ_p a) {
    this->sk = s;
    this->a = a;
}

PublicKey *Key::get_public_key() {
    return pk;
}

/*
 * bn namespace is for curve initialization
 */
PublicKey::PublicKey(NTL::ZZ p) {
    using namespace bn;
    CurveParam cp = CurveFp254BNb;
    Param::init(cp);
    NTL::ZZ_p::init(p);
    const Point &pt = selectPoint(cp);
    const Ec2 gt2(Fp2(Fp(pt.g2.aa), Fp(pt.g2.ab)), Fp2(Fp(pt.g2.ba), Fp(pt.g2.bb)));
    const Ec1 gt1(pt.g1.a, pt.g1.b);
    g1 = gt1;
    g2 = gt2;
}

PublicKey::~PublicKey() {
//    delete();
}

/*
 * Setup bilinear creates the powers of g1^s and g2^s
 */
void PublicKey::setup_bilinear(SecretKey *sk, bn::Ec1, bn::Ec2) {
    using namespace bn;
    using namespace NTL;
    Utils utils;
    ZZ_p s = sk->sk;
    const int q = SETS_MAX_SIZE;
    const char *s_str = utils.zToString(s);
    const mie::Vuint secret_key(s_str);
    free((char *) s_str);
    const char *a_str = utils.zToString(sk->a);
    const mie::Vuint a(a_str);
    free((char *) a_str);
    pubs_g1.push_back(g1);
    pubs_ga1.push_back(g1 * a);
    for (int i = 1; i < q + 1; i++) {
        pubs_g1.push_back(pubs_g1[i - 1] * secret_key);
        pubs_ga1.push_back(pubs_g1[i] * a);
    }
    pubs_g2.push_back(g2);
    pubs_ga2.push_back(g2 * a);
    for (int i = 1; i < q + 1; i++) {
        pubs_g2.push_back(pubs_g2[i - 1] * secret_key);
        pubs_ga2.push_back(pubs_g2[i] * a);
    }
}
