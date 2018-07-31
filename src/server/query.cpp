//
// Created by sauron on 7/18/18.
//

#include "server/query.h"

using namespace bn;
using namespace NTL;


bool cmp(const NTL::ZZ_p &lhs, const NTL::ZZ_p &rhs)
{
    Utils utils;
    char* x = utils.zToString(rhs);
    char* y = utils.zToString(lhs);
    return strcmp(x, y) > 0;
}

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
    std::set<NTL::ZZ_p, ZZ_p_compare> intersect;
    set_intersection(dataStructure->D[0].begin(), dataStructure->D[0].end(), dataStructure->D[1].begin(), dataStructure->D[1].end(), std::inserter(intersect, intersect.begin()), cmp);
    I = intersect;
    for(int i = 2; i < dataStructure->m; i++) {
        set_intersection(dataStructure->D[i].begin(), dataStructure->D[i].end(), I.begin(), I.end(), std::inserter(intersect, intersect.begin()), cmp);
        I = intersect;
    }
    *digest_I = utils.compute_digest_pub(I, pk->g1, pk);
//    PUT(*digest_I);
}

void Intersection::subset_witness(){
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    int len = dataStructure->m;
    for(int i = 0; i < len; i++) {
        w.clear();
        set_difference(dataStructure->D[i].begin(), dataStructure->D[i].end(), I.begin(), I.end(), std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for(unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p[i], c);

        Ec2 digest = pk->g2 * 0;
        int size = p[i].rep.length();
        for(int j = 0; j < size; j++){
            mie::Vuint temp(utils.zToString(p[i][j]));
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W[i] = digest;
    }

}

void Intersection::completeness_witness(){
    Utils utils;
    Ec1 g1 = pk->g1;
    xgcdTree();
    for(int i = 0; i < dataStructure->m; i++) {
        Ec1 digest1 = g1 * 0;
        polyS = q[i];
        for (int j = 0; j < polyS.rep.length(); j++) {
            const mie::Vuint temp(utils.zToString(polyS[j]));
            digest1 = digest1 + pk->pubs_g1[j] * temp;
        }
        (*Q[i]) = digest1;
    }
}

