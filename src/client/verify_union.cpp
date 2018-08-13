//
// Created by sauron on 8/2/18.
//
#include <client/verify_union.h>


VerifyUnion::VerifyUnion(PublicKey *pk, std::set<NTL::ZZ_p, ZZ_p_compare> union_ans, bn::Ec2 *W1[], bn::Ec2 *W2[], bn::Ec1 AuthD[], int size, std::vector<int> indices, std::vector<int> set_indices){
    Utils utils;
    this->pk = pk;
//    PUT("fuck");
    bn::Ec1 digest_test = utils.compute_digest_pub(union_ans, pk->g1, pk);
    this->digest_U = digest_test;
    this->union_ans = union_ans;
    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator it;
    for (it = union_ans.begin(); it != union_ans.end(); it++)
        U.push_back(*it);
    for(int i = 0; i < SETS_MAX_SIZE; i++)
        this->W1[i] = W1[i];
    for(int i = 0; i < SETS_MAX_NO; i++)
        this->W2[i] = W2[i];
    this->m = size;
    for(int i = 0; i < m; i++)
        this->AuthD[i] = AuthD[i];
    this->indices = indices;
    this->set_indices = set_indices;
}

bool VerifyUnion::verify_union() {
    using namespace::bn;
    Utils utils;
    Fp12 e1, e2, e3, e4;
    for(unsigned int i = 0; i < U.size(); i++) {
        const char* Ui_str = utils.zToString(U[i]);
        const mie::Vuint temp(Ui_str);
        delete[] Ui_str;
        Ec1 gsgi = pk->pubs_g1[1] + pk->g1 * temp;
        opt_atePairing(e1, *W1[i], gsgi);
        opt_atePairing(e2, pk->g2, AuthD[indices[set_indices[i]]]);
        if( e1 != e2){
            membershipwitness = false;
            return false;
        }
    }
    membershipwitness = true;
//    PUT(digest_U);
//    PUT(indices.size());
    opt_atePairing(e4, pk->g2, digest_U);
    for(unsigned int i = 0; i < indices.size(); i++) {
//        PUT(i);
        opt_atePairing(e3, *W2[indices[i]], AuthD[indices[i]]);
//        PUT(*W2[indices[i]]);
//        PUT(AuthD[indices[i]]);
//        PUT(e3);
//        PUT(e4);
        if (e3 != e4) {
            supersetnesswitness = false;
            return false;
        }
    }
    supersetnesswitness = true;
//    PUT(supersetnesswitness);
    return membershipwitness and supersetnesswitness;
}
