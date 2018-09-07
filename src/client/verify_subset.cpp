//
// Created by sauron on 8/2/18.
//
#include <client/verify_subset.h>


VerifySubset::VerifySubset(PublicKey *publicKey, DataStructure *dataStructure, bn::Ec2 *Q[], bn::Ec2 *W, bool answer,
                           int I, int J, NTL::ZZ_p y) {
    this->pk = publicKey;
    this->dataStructure = dataStructure;
    this->W = W;
    for (int i = 0; i < 2; i++)
        this->Q[i] = Q[i];
    this->answer = answer;
    this->y = y;
    this->I = I;
    this->J = J;
}

void VerifySubset::verify_subset() {
    if (answer)
        verified_subset = verifyPositive();
    else
        verified_subset = verifyNegetive();
}

// to verify positive answer, we have to check the correctness of subset witness as follow
bool VerifySubset::verifyPositive() {
    using namespace bn;
    Fp12 e1, e2;
    opt_atePairing(e1, *W, dataStructure->AuthD[J]);
    opt_atePairing(e2, pk->g2, dataStructure->AuthD[I]);
    if (e1 != e2) {
        verified_subset = false;
        return false;
    }
    return true;
}

/*
 * verify negative answer by checking that there is a member in J (y) which has empty intersection with I
 */
bool VerifySubset::verifyNegetive() {
    using namespace bn;
    Utils utils;
    Fp12 e1, e2, e3, e4, e5;
    char *y_str = utils.zToString(y);
    const mie::Vuint temp(y_str);
    free(y_str);
    Ec1 gygs = pk->pubs_g1[1] + pk->g1 * temp;
    opt_atePairing(e1, *W, gygs);
    opt_atePairing(e2, pk->g2, dataStructure->AuthD[J]);
    if (e1 != e2) {
        verified_subset = false;
        return false;
    }
    opt_atePairing(e5, pk->g2, pk->g1);
    opt_atePairing(e3, *Q[1], gygs);
    opt_atePairing(e4, *Q[0], dataStructure->AuthD[I]);
    if (e3 * e4 != e5) {
        verified_subset = false;
        return false;
    }
    verified_subset = true;
    return true;
}
