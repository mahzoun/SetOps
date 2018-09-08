//
// Created by sauron on 7/17/18.
//

#include "utils/utils.h"

using namespace NTL;
using namespace bn;

// return true iff rhs < lhs
bool ZZ_p_compare::operator()(const NTL::ZZ_p &rhs, const NTL::ZZ_p &lhs) const {
    Utils utils;
    char *s1 = utils.zToString(rhs);
    char *s2 = utils.zToString(lhs);
    bool b = strcmp(s1, s2) < 0;
    free(s1);
    free(s2);
    return b;
}

// use string stream to convert Ec1 to string
char *Utils::Ec1ToString(Ec1 z) {
    std::stringstream buffer;
    buffer << z;
    return strdup(buffer.str().c_str());
}

// use string stream to convert Ec2 to string
char *Utils::Ec2ToString(Ec2 z) {
    std::stringstream buffer;
    buffer << z;
    return strdup(buffer.str().c_str());
}

// compute digest using public key
bn::Ec1 Utils::compute_digest_pub(std::set<NTL::ZZ_p, ZZ_p_compare> intersection, const bn::Ec1 g1, PublicKey *pk) {
    std::vector<NTL::ZZ_p> array(intersection.begin(), intersection.end());
    Ec1 digest = g1 * 0;
    if (array.size() == 0)
        return g1;

    ZZ_pX f, poly;
    poly = ZZ_pX(INIT_MONO, array.size());
    vec_ZZ_p c;
    c.SetLength(array.size());
    for (unsigned int i = 0; i < array.size(); i++)
        c[i] = conv<ZZ_p>(-array[i]);
    BuildFromRoots(poly, c);
    //compute digest in the following loop
    for (unsigned int i = 0; i < array.size() + 1; i++) {
        char *str = zToString(poly[i]);
        const mie::Vuint temp(str);
        free(str);
        digest = digest + pk->pubs_g1[i] * temp;
    }
    return digest;
}

//compute accumulation of a set = g * (s + x1)(s + x2)...(s + xn)
bn::Ec1 Utils::compute_digest(std::set<NTL::ZZ_p, ZZ_p_compare> set, const bn::Ec1 g1, SecretKey *sk) {
    Ec1 digest = g1 * 1;
    if (set.size() == 0)
        return digest;

    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator it;
    ZZ_p temp1 = conv<ZZ_p>(1);

    for (it = set.begin(); it != set.end(); it++)
        temp1 *= (sk->sk) + *it;
    const mie::Vuint temp(zToString(temp1));
    digest = g1 * temp;
    return digest;
}

// compute digest using public key
bn::Ec2 Utils::compute_digest_pub(std::set<NTL::ZZ_p, ZZ_p_compare> intersection, const bn::Ec2 g2, PublicKey *pk) {
    std::vector<NTL::ZZ_p> array(intersection.begin(), intersection.end());
    Ec2 digest = g2 * 0;
    if (array.size() == 0)
        return g2;

    ZZ_pX f, poly;
    poly = ZZ_pX(INIT_MONO, array.size());
    vec_ZZ_p c;
    c.SetLength(array.size());
    for (unsigned int i = 0; i < array.size(); i++)
        c[i] = conv<ZZ_p>(-array[i]);
    BuildFromRoots(poly, c);
    //compute digest in the following loop
    for (unsigned int i = 0; i < array.size() + 1; i++) {
        char *str = zToString(poly[i]);
        const mie::Vuint temp(str);
        free(str);
        digest = digest + pk->pubs_g2[i] * temp;
    }
    return digest;
}

// compute digest*a using public key
bn::Ec2 Utils::compute_digest_puba(std::set<NTL::ZZ_p, ZZ_p_compare> intersection, const bn::Ec2 g2, PublicKey *pk) {
    std::vector<NTL::ZZ_p> array(intersection.begin(), intersection.end());
    Ec2 digest = g2 * 0;
    if (array.size() == 0)
        return pk->pubs_ga2[0];

    ZZ_pX f, poly;
    poly = ZZ_pX(INIT_MONO, array.size());
    vec_ZZ_p c;
    c.SetLength(array.size());
    for (unsigned int i = 0; i < array.size(); i++)
        c[i] = conv<ZZ_p>(-array[i]);
    BuildFromRoots(poly, c);
    for (unsigned int i = 0; i < array.size() + 1; i++) {
        char *str = zToString(poly[i]);
        const mie::Vuint temp(str);
        free(str);
        digest = digest + pk->pubs_ga2[i] * temp;
    }
    return digest;
}

char *Utils::concat(const char *s1, const char *s2) {
    debug("concating %s and %s", s1, s2);
    char *result = new char[strlen(s1) + strlen(s2) + 1]; // +1 for the null-terminator
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

void Utils::sha256(unsigned char *outputBuffer, char *string , int index) {
    char *idx = new char[SET_NO_LEN];
    char *string1 = new char[strlen(string) + SET_NO_LEN + 1];
    sprintf(idx, "%d", index);
    strcpy(string1, string);
    strcat(string1, idx);
    sha256(outputBuffer, string1);
    delete[] string1;
    delete[] idx;
}

//outputBuffer = sha256(string)
//TODO the value is octect, it should be decimal
void Utils::sha256(unsigned char *outputBuffer, char *string) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf((char *) outputBuffer + (i * 2), SHA256_DIGEST_LENGTH, "%02o", hash[i]);
    }
    outputBuffer[64] = 0;
}


ZZ_p Utils::StringToz(char *str) {
    ZZ temp = conv<ZZ>(str);
    return conv<ZZ_p>(temp);
}

char *Utils::zToString(NTL::ZZ_p &z) { //TODO mem leak :)
    std::stringstream buffer;
    buffer << z;
    char *zzstring = strdup(buffer.str().c_str());
    return zzstring;
}

char *Utils::zToString(const NTL::ZZ_p &z) {
    std::stringstream buffer;
    buffer << z;

    char *zzstring = strdup(buffer.str().c_str());
    return zzstring;
}
