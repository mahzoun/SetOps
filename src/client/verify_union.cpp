//
// Created by sauron on 8/2/18.
//
#include <client/verify_union.h>


VerifyUnion::VerifyUnion(PublicKey *pk, std::set<NTL::ZZ_p, ZZ_p_compare> ans, std::vector<std::vector<QueryNode>> &t,
                         int size, std::vector<int> &ind) {
    Utils utils;
    this->pk = pk;
    union_ans = ans;
    tree = t;
    m = size;
    indices = ind;
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