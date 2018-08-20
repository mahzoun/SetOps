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
    Utils utils;
    bool b = verified_intersection();
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