//
// Created by sauron on 7/18/18.
//

#include "server/query.h"

using namespace bn;
using namespace NTL;

//void Intersection::gamma(DataStructure *dataStructure, PublicKey *pk) {
//    int len = dataStructure->m;
//    int depth = 0;
//    while(len > 0){
//        depth++;
//        if(len%2 == 0) {
//            for (int i = 0; i < len/2; i++) {
//                dataStructure->gamma[depth][i][0] = calNodeGamma(pk, dataStructure->digest[depth - 1][2 * i], dataStructure->digest[depth - 1][2*i + 1], 1);
//                dataStructure->gamma[depth][i][1] = calNodeGamma(pk, dataStructure->digest[depth - 1][2 * i], dataStructure->digest[depth - 1][2*i + 1], 0);
//            }
//        }
//        else{
//            for (int i = 0; i < len/2 - 1; i += 2) {
//                dataStructure->gamma[depth][i][0] = calNodeGamma(pk, dataStructure->digest[depth - 1][2 * i], dataStructure->digest[depth - 1][2*i + 1], 1);
//                dataStructure->gamma[depth][i][1] = calNodeGamma(pk, dataStructure->digest[depth - 1][2 * i], dataStructure->digest[depth - 1][2*i + 1], 0);
//            }
//            dataStructure->gamma[depth][len/2][0] = calNodeGamma(pk, dataStructure->digest[depth - 1][len - 1], dataStructure->digest[depth - 1][len - 1], 1);
//            dataStructure->gamma[depth][len/2][1] = calNodeGamma(pk, dataStructure->digest[depth - 1][len - 1], dataStructure->digest[depth - 1][len - 1], 0);
//        }
//        len/=2;
//    }
//}

////TODO this functions is dirty, refactor it
//bn::Ec1 Intersection::calNodeGamma(PublicKey *pk, bn::Ec1 h1, bn::Ec1 h2, int n) {
//    Utils utils;
//    bn::Ec1 digest = pk->g1 * 0;
//    if( n == 1) {
//        NTL::ZZ_p temp = NTL::conv<NTL::ZZ_p>(1);
//        unsigned char *H1;
//        H1 = utils.sha256(utils.Ec1ToString(h1));
//        //TODO 250?!
//        H1 = (unsigned char *)strndup((char*)H1, 250);
//        NTL::ZZ_p x1 = utils.StringToz((char *)H1);
//        temp *= x1;
//        const mie::Vuint temp1(zToString(temp));
//        const mie::Vuint X1(zToString(x1));
//        digest = pk->pubs_g1[1] * temp1 + pk->g1 * X1;
//        return digest;
//    }
//    else if( n == 0){
//        NTL::ZZ_p temp = NTL::conv<NTL::ZZ_p>(1);
//        unsigned char *H2;
//        H2 = utils.sha256(utils.Ec1ToString(h2));
//        //TODO 250?!
//        H2 = (unsigned char *)strndup((char*)H2, 250);
//        NTL::ZZ_p x2 = utils.StringToz((char *)H2);
//        temp *= x2;
//        const mie::Vuint X2(zToString(x2));
//        const mie::Vuint temp1(zToString(temp));
//        digest = pk->pubs_g1[1] * temp1 + pk->g1 * X2;
//        return digest;
//    }
//   return digest;
//}

void Intersection::xgcdTree() {
    std::vector<int> w[SETS_MAX_NO];
    q[0] = 1;
    for(int i = 0; i < dataStructure->m - 1; i++){
        XGCD(polyD,polyS,polyT, p[i], p[i+1]);
        q[i] *= polyS;
        q[i+1] = polyT;
        p[i+1] = polyD;
        if(!IsZero(q[i] * q[i+1]))
            for(int j = i - 1; j >= 0; j--)
                q[j] *= q[i];
    }

}

Intersection::Intersection(const std::vector<int> indices, PublicKey* pk, DataStructure* dataStructure){
//    this->gamma(dataStructure, pk);
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
    for(int i = 0; i < SETS_MAX_NO; i++)
        this->W[i] = new bn::Ec2;
    for(int i = 0; i < SETS_MAX_NO; i++)
        this->Q[i] = new bn::Ec1;
    this->digest_I = new bn::Ec1;
    polyA=ZZ_pX(INIT_MONO,0);
    polyB=ZZ_pX(INIT_MONO,0);
    polyS=ZZ_pX(INIT_MONO,0);
    polyT=ZZ_pX(INIT_MONO,0);
    polyD=ZZ_pX(INIT_MONO,0);

}

void Intersection::intersect(){
    Utils utils;
    std::multiset<int> intersect;
    set_intersection(dataStructure->D[0].begin(), dataStructure->D[0].end(), dataStructure->D[1].begin(), dataStructure->D[1].end(), std::inserter(intersect, intersect.begin()));
    I = intersect;
    for(int i = 2; i < dataStructure->m; i++) {
        set_intersection(dataStructure->D[i].begin(), dataStructure->D[i].end(), I.begin(), I.end(), std::inserter(intersect, intersect.begin()));
        I = intersect;
    }
    *digest_I = utils.compute_digest_pub(I, pk->g1, pk);
//    gamma(dataStructure, pk);
}

void Intersection::subset_witness(){
    std::vector<int> w;
    int len = dataStructure->m;
    for(int i = 0; i < len; i++) {
        w.clear();
        set_difference(dataStructure->D[i].begin(), dataStructure->D[i].end(), I.begin(), I.end(), std::inserter(w, w.begin()));
        c.SetLength(w.size());
        for(unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p[i], c);

        Ec2 digest = pk->g2 * 0;
        int size = p[i].rep.length();
        for(int j = 0; j < size; j++){
            mie::Vuint temp(zToString(p[i][j]));
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W[i] = digest;
    }

}

void Intersection::completeness_witness(){
    Ec1 g1 = pk->g1;
    xgcdTree();
    for(int i = 0; i < dataStructure->m; i++) {
        Ec1 digest1 = g1 * 0;
        polyS = q[i];
        for (int j = 0; j < polyS.rep.length(); j++) {
            const mie::Vuint temp(zToString(polyS[j]));
            digest1 = digest1 + pk->pubs_g1[j] * temp;
        }
        (*Q[i]) = digest1;
    }
}

