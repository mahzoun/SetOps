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
    set_intersection(dataStructure->D[indices[0]].begin(), dataStructure->D[indices[0]].end(), dataStructure->D[indices[1]].begin(), dataStructure->D[indices[1]].end(), std::inserter(intersect, intersect.begin()), cmp);
    I = intersect;
    PUT(I.size());
    for(int i = 2; i < indices.size(); i++) {
        intersect.clear();
        set_intersection(dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), I.begin(), I.end(), std::inserter(intersect, intersect.begin()), cmp);
        I = intersect;
    }
    *digest_I = utils.compute_digest_pub(I, pk->g1, pk);
}

void Intersection::subset_witness(){
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    int len = dataStructure->m;
    for(int i = 0; i < indices.size(); i++) {
        w.clear();
        set_difference(dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), I.begin(), I.end(), std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for(unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p[indices[i]], c);

        Ec2 digest = pk->g2 * 0;
        int size = p[indices[i]].rep.length();
        for(int j = 0; j < size; j++){
            mie::Vuint temp(utils.zToString(p[indices[i]][j]));
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W[indices[i]] = digest;
    }

}

void Intersection::completeness_witness(){
    Utils utils;
    Ec1 g1 = pk->g1;
    xgcdTree();
    for(int i = 0; i < indices.size(); i++) {
        Ec1 digest1 = g1 * 0;
        polyS = q[indices[i]];
        int poly_size = polyS.rep.length();
        for (int j = 0; j < poly_size; j++) {
            const mie::Vuint temp(utils.zToString(polyS[j]));
            digest1 = digest1 + pk->pubs_g1[j] * temp;
        }
        (*Q[indices[i]]) = digest1;
    }
}

Union::Union(const std::vector<int> indices, PublicKey* pk, DataStructure* dataStructure){
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
    for(int i = 0; i < SETS_MAX_NO; i++) {
        this->W1[i] = new bn::Ec2;
        this->W2[i] = new bn::Ec2;
    }
}

void Union::unionSets() {
    std::set<NTL::ZZ_p, ZZ_p_compare> setsunion;
    set_union(dataStructure->D[indices[0]].begin(), dataStructure->D[indices[0]].end(), dataStructure->D[indices[1]].begin(), dataStructure->D[indices[1]].end(), std::inserter(setsunion, setsunion.begin()), cmp);
    U = setsunion;
    for(int i = 2; i < indices.size(); i++) {
        set_union(dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), U.begin(), U.end(), std::inserter(setsunion, setsunion.begin()), cmp);
        U = setsunion;
    }
}


void Union::membership_witness() {
    Utils utils;
    std::vector<NTL::ZZ_p> w, U_tmp;
    int len = dataStructure->m;
    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator it;
    for (it = U.begin(); it != U.end(); it++)
        U_tmp.push_back(*it);
    for (int i = 0; i < U_tmp.size(); i++) {
        w.clear();
        std::vector<NTL::ZZ_p> tmp;
        tmp.push_back(U_tmp[i]);
        int superset = 0;
        for (int j = 0; j < indices.size(); j++) {
            if (dataStructure->D[indices[j]].find(U_tmp[i]) != dataStructure->D[indices[j]].end()) {
                set_indices.push_back(j);
                superset = indices[j];
                break;
            }
        }
        set_difference(dataStructure->D[superset].begin(), dataStructure->D[superset].end(), tmp.begin(), tmp.end(),
                       std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for (unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }

        BuildFromRoots(p, c);
        Ec2 digest = pk->g2 * 0;
        int size = p.rep.length();
        for (int j = 0; j < size; j++) {
            mie::Vuint temp(utils.zToString(p[j]));
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W1[i] = digest;
//        std::cout<<"W1[" << i << "]\t" << *W1[i] << "\n";
    }
}

void Union::superset_witness(){
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    int len = dataStructure->m;
    for(int i = 0; i < indices.size(); i++) {
        w.clear();
        set_difference(U.begin(), U.end(), dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for(unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p, c);

        Ec2 digest = pk->g2 * 0;
        int size = p.rep.length();
        for(int j = 0; j < size; j++){
            mie::Vuint temp(utils.zToString(p[j]));
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W2[indices[i]] = digest;
//        std::cout<<"W2[" << i << "]\t" << *W2[i] << "\n";
    }
}

Subset::Subset(int I, int J, PublicKey *publicKey, DataStructure *dataStructure) {
    this->index[0] = I;
    this->index[1] = J;
    this->pk = publicKey;
    this->dataStructure = dataStructure;
    this->answer = 0;
    this->W = new bn::Ec2;
    for(int i = 0; i < 2; i++)
        this->Q[i] = new bn::Ec1;

}

void Subset::subset() {
    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator first1, last1, first2, last2;
    first1 = dataStructure->D[index[0]].begin();
    last1 = dataStructure->D[index[0]].end();
    first2 = dataStructure->D[index[1]].begin();
    last2 = dataStructure->D[index[1]].end();
    while (first2!=last2) {
        if (first1==last1 || cmp(*first2, *first1)) {
            answer = false;
            y = *first2;
            return;
        }
        if (!cmp(*first1, *first2))
            ++first2;
        ++first1;
    }
    answer = true;
}

void Subset::positiveWitness() {
    if(!answer)
        return;
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    w.clear();
    set_difference(dataStructure->D[index[0]].begin(), dataStructure->D[index[0]].end(),
                   dataStructure->D[index[1]].begin(), dataStructure->D[index[1]].end(), std::inserter(w, w.begin()), cmp);
    c.SetLength(w.size());
    for(unsigned int j = 0; j < w.size(); j++) {
        c[j] = -w[j];
    }
    BuildFromRoots(p[1], c);
    Ec2 digest = pk->g2 * 0;
    int size = p[1].rep.length();
    for(int j = 0; j < size; j++){
        mie::Vuint temp(utils.zToString(p[1][j]));
        digest = digest + pk->pubs_g2[j] * temp;
    }
    *W = digest;
}

void Subset::negativeWitness() {
    if(answer)
        return;

    Utils utils;
    std::vector<NTL::ZZ_p> w;
    w.clear();
    std::vector<NTL::ZZ_p> tmp;
    tmp.push_back(this->y);
    set_difference(dataStructure->D[index[1]].begin(), dataStructure->D[index[1]].end(), tmp.begin(), tmp.end(),
                   std::inserter(w, w.begin()), cmp);
    c.SetLength(w.size());
    for (unsigned int j = 0; j < w.size(); j++) {
        c[j] = -w[j];
    }
    BuildFromRoots(p[0], c);
    Ec2 digest = pk->g2 * 0;
    int size = p[0].rep.length();
    for (int j = 0; j < size; j++) {
        mie::Vuint temp(utils.zToString(p[0][j]));
        digest = digest + pk->pubs_g2[j] * temp;
    }
    *W = digest;
    tmp_c.SetLength(1);
    tmp_c[0] = y;
    BuildFromRoots(p[1], tmp_c);
    digest = pk->g2 * 0;
    XGCD(polyD, polyS, polyT, q[0], q[1]);
    for(int i = 0; i < 2; i++) {
        Ec1 digest1 = pk->g1 * 0;
        int poly_size = q[i].rep.length();
        for (int j = 0; j < poly_size; j++) {
            const mie::Vuint temp(utils.zToString(q[i][j]));
            digest1 = digest1 + pk->pubs_g1[j] * temp;
        }
        *Q[i] = digest1;
    }
}
