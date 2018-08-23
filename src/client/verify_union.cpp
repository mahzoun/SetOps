//
// Created by sauron on 8/2/18.
//
#include <client/verify_union.h>


VerifyUnion::VerifyUnion(PublicKey *pk, std::set<NTL::ZZ_p, ZZ_p_compare> ans, std::vector<std::vector<QueryNode>> &t,
                         int size, std::vector<int> &ind) {
    Utils utils;
    this->pk = pk;
    tree = t;
    m = size;
}

bool VerifyUnion::verify_union() {
    using namespace ::bn;
    bool b = verified_intersection() and verified_union() and verified_set();
    return b;
}

bool VerifyUnion::verified_intersection() {
    bool result = true;
    bn::Fp12 e1, e2, e3, e4, e5;
    for (int i = 1; i < tree.size(); i++) { //depth
        for (int j = 0; j < tree[i].size(); j++) { //lentgh
            for (int k = 0; k < SMALL_QUERY_SIZE; k++) {
                opt_atePairing(e1, tree[i][j].W[k], tree[i][j].HI);
                opt_atePairing(e2, pk->g2, tree[i - 1][j * 2 + k].F1);
                if (e1 != e2) {
                    result = false;
                }
            }
            e3 = 1;
            opt_atePairing(e5, pk->g2, pk->g1);
            for (unsigned int k = 0; k < SMALL_QUERY_SIZE; k++) {
                opt_atePairing(e4, tree[i][j].W[k], tree[i][j].Q[k]);
                e3 *= e4;
            }
            if (e3 != e5) {
                result = false;
            }
        }
    }
    return result;
}

bool VerifyUnion::verified_union() {
    bool result = true;
    bn::Fp12 e1, e2;
    for (int i = 1; i < tree.size(); i++) {
        for (int j = 0; j < tree[i].size(); j++) {
            opt_atePairing(e1, tree[i - 1][j * 2].F2, tree[i - 1][j * 2 + 1].F1);
            opt_atePairing(e2, tree[i][j].HU, tree[i][j].HI);
            if (e1 != e2) {
                result = false;
            }
        }
    }
    return result;
}

bool VerifyUnion::verified_set() {
    bool result = true;
    bn::Fp12 e1, e2;
    for (int i = 1; i < tree.size(); i++) {
        for (int j = 0; j < tree[i].size(); j++) {
            opt_atePairing(e1, tree[i][j].HU, pk->pubs_ga1[0]);
            opt_atePairing(e2, tree[i][j].HUp, pk->g1);
            if (e1 != e2) {
                result = false;
            }
            opt_atePairing(e1, pk->pubs_ga2[0], tree[i][j].HI);
            opt_atePairing(e2, tree[i][j].HIp, pk->g1);
            if (e1 != e2) {
                result = false;
            }
        }
    }
    return result;
}


VerifyUnion2::VerifyUnion2(PublicKey *pk, std::set<NTL::ZZ_p, ZZ_p_compare> union_ans, bn::Ec2 *W1[], bn::Ec2 *W2[],
                           bn::Ec1 AuthD[], int size, std::vector<int> indices, std::vector<int> set_indices) {
    Utils utils;
    this->pk = pk;
    bn::Ec1 digest_test = utils.compute_digest_pub(union_ans, pk->g1, pk);
    this->digest_U = digest_test;
    this->union_ans = union_ans;
    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator it;
    for (it = union_ans.begin(); it != union_ans.end(); it++)
        U.push_back(*it);
    for (int i = 0; i < SETS_MAX_SIZE; i++)
        this->W1[i] = W1[i];
    for (int i = 0; i < SETS_MAX_NO; i++)
        this->W2[i] = W2[i];
    this->m = size;
    for (int i = 0; i < m; i++)
        this->AuthD[i] = AuthD[i];
    this->indices = indices;
    this->set_indices = set_indices;
}

bool VerifyUnion2::verify_union() {
    using namespace ::bn;
    Utils utils;
    Fp12 e1, e2, e3, e4;
    for (unsigned int i = 0; i < U.size(); i++) {
        char *Ui_str = utils.zToString(U[i]);
        const mie::Vuint temp(Ui_str);
        free(Ui_str);
        Ec1 gsgi = pk->pubs_g1[1] + pk->g1 * temp;
        opt_atePairing(e1, *W1[i], gsgi);
        opt_atePairing(e2, pk->g2, AuthD[set_indices[i]]);
        if (e1 != e2) {
            membershipwitness = false;
            return false;
        }
    }
    membershipwitness = true;
    opt_atePairing(e4, pk->g2, digest_U);
    for (unsigned int i = 0; i < indices.size(); i++) {
        opt_atePairing(e3, *W2[indices[i]], AuthD[indices[i]]);
        if (e3 != e4) {
            supersetnesswitness = false;
            return false;
        }
    }
    supersetnesswitness = true;
    return membershipwitness and supersetnesswitness;
}