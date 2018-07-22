//
// Created by sauron on 7/18/18.
//

#include "server/query.h"

using namespace bn;
using namespace NTL;

Intersection::Intersection(const std::vector<int> indices, PublicKey* pk, DataStructure* dataStructure){
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
    this->W1 = new bn::Ec2;
    this->W2 = new bn::Ec2;
    this->Q1 = new bn::Ec1;
    this->Q2 = new bn::Ec1;
    this->digest_I = new bn::Ec1;
    polyA=ZZ_pX(INIT_MONO,0);
    polyB=ZZ_pX(INIT_MONO,0);
    polyS=ZZ_pX(INIT_MONO,0);
    polyT=ZZ_pX(INIT_MONO,0);
    polyD=ZZ_pX(INIT_MONO,0);

}

void Intersection::intersect(){
    Utils utils;
    std::set<int> intersect;
    std::set<int> s1 = dataStructure->D[0], s2 = dataStructure->D[1];
    set_intersection(s1.begin(),s1.end(),s2.begin(),s2.end(), std::inserter(intersect, intersect.begin()));
    this->I = intersect;
//    std::cout<<"Intersection is: \n";
//    for(auto x:I)
//        std::cout<< x << "\t";
//    std::cout<< "\n";
    *digest_I = utils.compute_digest_pub(I, pk->g1, pk);
//    PUT(*digest_I);
}

void Intersection::subset_witness(){
    std::vector<int> w1, w2;
    std::set<int> s1 = dataStructure->D[0], s2 = dataStructure->D[1];
    set_difference(s1.begin(),s1.end(),I.begin(),I.end(), std::inserter(w1, w1.begin()));
    set_difference(s2.begin(),s2.end(),I.begin(),I.end(), std::inserter(w2, w2.begin()));
//    Ec1 g1 = pk->g1;
    Ec2 g2 = pk->g2;
    Ec2 *W1 = this->W1;
    Ec2 *W2 = this->W2;
    c.SetLength(w1.size());
    for(int i=0;i<w1.size();i++)
        c[i] = -w1[i];
    BuildFromRoots(polyA,c);
    c.SetLength(w2.size());
    for(int i=0;i<w2.size();i++)
        c[i] = -w2[i];
    BuildFromRoots(polyB,c);

    std::cout << "fuck0\n";
    Ec2 digest = g2*0;
    int size = polyA.rep.length();
    for(int i = 0; i < size; i++){
        mie::Vuint temp(zToString(polyA[i]));
//        std::cout<<i<<"\t" << size << "\t" <<  temp << "\n";
        digest = digest + pk->pubs_g2[i] * temp;
    }
    (*W1) = digest;
    std::cout << "fuck\n";
    digest = g2*0;
    for(int i=0;i<polyB.rep.length();i++){

        const mie::Vuint temp(zToString(polyB[i]));
        digest = digest + pk->pubs_g2[i] * temp;
    }
    (*W2) = digest;

    std::cout<<"Generated subset witness: \n";
    PUT(*W1);
    PUT(*W2);


}

void Intersection::completeness_witness(){
    Ec1 g1 = pk->g1;
    Ec2 g2 = pk->g2;
    XGCD(polyD,polyS,polyT,polyA,polyB);

    Ec1 digest1 = g1*0;
    for(int i=0;i<polyS.rep.length();i++){

        const mie::Vuint temp(zToString(polyS[i]));
        digest1 = digest1 + pk->pubs_g1[i] * temp;
    }
    (*Q1) = digest1;

    digest1 = g1*0;
    for(int i=0;i<polyT.rep.length();i++){

        const mie::Vuint temp(zToString(polyT[i]));
        digest1 = digest1 + pk->pubs_g1[i] * temp;
    }
    (*Q2) = digest1;

    std::cout<<"Generated completeness witness: \n";
//    PUT(*Q1);
//    PUT(*Q2);
}

