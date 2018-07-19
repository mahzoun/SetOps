//
// Created by sauron on 7/18/18.
//

#include "query.h"


bool cmp(NTL::ZZ_p &x, NTL::ZZ_p &y) {
    return NTL::rep(x) < NTL::rep(y);
}


Intersection::Intersection(const std::vector<int> indices, PublicKey* pk, DataStructure* dataStructure){
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
}
void Intersection::intersect(){
    std::set<int> intersect;
    std::set<int> s1 = dataStructure->D[0], s2 = dataStructure->D[1];
    set_intersection(s1.begin(),s1.end(),s2.begin(),s2.end(), std::inserter(intersect, intersect.begin()));
    this->I = intersect;
    std::cout<<"Intersection is: \n";
    for(auto x:I)
        std::cout<< x << "\t";
    std::cout<< "\n";
}
void Intersection::subset_witness(){
    using namespace NTL;
    using namespace bn;
    std::vector<int> w1, w2;
    std::set<int> s1 = dataStructure->D[0], s2 = dataStructure->D[1];
    set_difference(s1.begin(),s1.end(),I.begin(),I.end(), std::inserter(w1, w1.begin()));
    set_difference(s2.begin(),s2.end(),I.begin(),I.end(), std::inserter(w2, w2.begin()));
    Ec1 g1 = pk->g1;
    Ec2 g2 = pk->g2;
    Ec2 *W1 = new Ec2, *W2 = new Ec2;
    vec_ZZ_p c;

    ZZ_pX polyA,polyB,polyS,polyT,polyD;
    polyA=ZZ_pX(INIT_MONO,0);
    polyB=ZZ_pX(INIT_MONO,0);
    polyS=ZZ_pX(INIT_MONO,0);
    polyT=ZZ_pX(INIT_MONO,0);
    polyD=ZZ_pX(INIT_MONO,0);

    c.SetLength(w1.size());
    for(int i=0;i<w1.size();i++)
        c[i] = -w1[i];
    BuildFromRoots(polyA,c);

    c.SetLength(w2.size());
    for(int i=0;i<w2.size();i++)
        c[i] = -w2[i];
    BuildFromRoots(polyB,c);

    Ec2 digest = g2*0;
    for(int i=0;i<polyA.rep.length();i++){
        const mie::Vuint temp(zToString(polyA[i]));
        digest = digest + pk->pubs_g2[i] * temp;
    }
    (*W1) = digest;

    digest = g2*0;
    for(int i=0;i<polyB.rep.length();i++){

        const mie::Vuint temp(zToString(polyB[i]));
        digest = digest + pk->pubs_g2[i] * temp;
    }
    (*W2) = digest;

    std::set<int>::iterator it;

    std::cout<<"Generated subset witness: \n";
    PUT(*W1);
    PUT(*W2);
}


void completeness_witness(){

}
