//
// Created by sauron on 7/17/18.
//

#include "utils/utils.h"

//
//char* zToString(NTL::ZZ_p &z) {
//    std::stringstream buffer;
//    buffer << z;
//
//    char *zzstring = strdup(buffer.str().c_str());
//    return zzstring;
//}
using namespace NTL;
using namespace bn;


char* Utils::Ec1ToString(Ec1 z){
    std::stringstream buffer;
    buffer << z;
    char *res = strdup(buffer.str().c_str());
    return res;
}

bn::Ec1 Utils::compute_digest_pub(std::multiset<int> intersection, const bn::Ec1 g1, PublicKey *pk){
    std::vector<int> array(intersection.begin(), intersection.end());
    Ec1 digest = g1*0;
    if(array.size() == 0)
        return digest;

    ZZ_pX f, poly;
    poly=ZZ_pX(INIT_MONO, array.size());
    vec_ZZ_p c;
    c.SetLength(array.size());
    for(int i = 0 ; i < array.size(); i++)
        c[i] = conv<ZZ_p>(-array[i]);

    BuildFromRoots(poly, c);
    for(int i = 0; i < array.size() + 1; i++){
        const mie::Vuint temp(zToString(poly[i]));
        digest = digest + pk->pubs_g1[i] * temp;
    }
    return digest;
}

bn::Ec1 Utils::compute_digest(std::multiset<int> set, const bn::Ec1 g1, SecretKey *sk){
    std::vector<int> array(set.begin(), set.end());
    Ec1 digest = g1*1;

    if(array.size() == 0)
        return digest;

    ZZ_p temp1 = conv<ZZ_p>(1);

    for(int i = 0; i < array.size(); i++){
        temp1 *= (sk->sk) + array[i];

    }

    const mie::Vuint temp(zToString(temp1));
    digest = g1 * temp;
    return digest;
}


char* Utils::concat(const char *s1, const char *s2)
{
    char *result = new char[strlen(s1) + strlen(s2) + 1]; // +1 for the null-terminator
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

unsigned char* Utils::sha256(char *string)
{
    //TODO return value is octect :)
    unsigned char *outputBuffer = new unsigned char[65];
    //TODO fix length
    unsigned char *final = new unsigned char[200];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf((char*)outputBuffer + (i * 2), "%02o", hash[i]);
    }
    outputBuffer[64] = 0;
    return outputBuffer;
}



ZZ_p Utils::StringToz(char* str){
    ZZ temp=conv<ZZ>(str);
    return conv<ZZ_p>(temp);
}

