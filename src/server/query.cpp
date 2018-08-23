//
// Created by sauron on 7/18/18.
//

#include "server/query.h"

using namespace bn;
using namespace NTL;


bool cmp(const NTL::ZZ_p &lhs, const NTL::ZZ_p &rhs) {
    Utils utils;
    char *x = utils.zToString(rhs);
    char *y = utils.zToString(lhs);
    bool b = strcmp(x, y) > 0;
    free(x);
    free(y);
    return b;
}

void Intersection::xgcdTree() {
    q[0] = 1;
    for (int i = 0; i < dataStructure->m - 1; i++) {
        try {
            XGCD(polyD, polyS, polyT, p[i], p[i + 1]);
            q[i] *= polyS;
            q[i + 1] = polyT;
            p[i + 1] = polyD;
            if (!IsZero(q[i] * q[i + 1]))
                for (int j = i - 1; j >= 0; j--)
                    q[j] *= q[i];
        }
        catch (exception &e) {
            std::cerr << q[i] << "\t" << q[i + 1] << "\t" << p[i + 1] << "\n";
            std::cerr << e.what() << "\n";
        }
    }

}

Intersection::Intersection(const std::vector<int> indices, PublicKey *pk, DataStructure *dataStructure) {
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
    for (int i = 0; i < SETS_MAX_NO; i++)
        this->W[i] = new bn::Ec2;
    for (int i = 0; i < SETS_MAX_NO; i++)
        this->Q[i] = new bn::Ec1;
    this->digest_I = new bn::Ec1;
    polyA = ZZ_pX(INIT_MONO, 0);
    polyB = ZZ_pX(INIT_MONO, 0);
    polyS = ZZ_pX(INIT_MONO, 0);
    polyT = ZZ_pX(INIT_MONO, 0);
    polyD = ZZ_pX(INIT_MONO, 0);
}

Intersection::~Intersection() {
    for (int i = 0; i < SETS_MAX_NO; i++)
        if (W[i])
            delete W[i];
    for (int i = 0; i < SETS_MAX_NO; i++)
        if (Q[i])
            delete Q[i];
    if (digest_I)
        delete (digest_I);
}

void Intersection::intersect() {
    Utils utils;
    std::set<NTL::ZZ_p, ZZ_p_compare> intersect;
    debug("Intersect the sets %d and %d", indices[0], indices[1]);
    set_intersection(dataStructure->D[indices[0]].begin(), dataStructure->D[indices[0]].end(),
                     dataStructure->D[indices[1]].begin(), dataStructure->D[indices[1]].end(),
                     std::inserter(intersect, intersect.begin()), cmp);
    I = intersect;

    for (unsigned int i = 2; i < indices.size(); i++) {
        intersect.clear();
        set_intersection(dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), I.begin(), I.end(),
                         std::inserter(intersect, intersect.begin()), cmp);
        debug("Intersect the sets I and %d", indices[i]);
        I = intersect;
    }
    *digest_I = utils.compute_digest_pub(I, pk->g1, pk);
    DEBUG("Digest of Intersection set is: ", *digest_I);
}

void Intersection::subset_witness() {
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    for (unsigned int i = 0; i < indices.size(); i++) {
        w.clear();
        set_difference(dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), I.begin(), I.end(),
                       std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for (unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p[indices[i]], c);

        Ec2 digest = pk->g2 * 0;
        int size = p[indices[i]].rep.length();
        for (int j = 0; j < size; j++) {
            const char *str = utils.zToString(p[indices[i]][j]);
            mie::Vuint temp(str);
            free((char *) str);
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W[indices[i]] = digest;
        DEBUGINDEX("Subset witness for ", indices[i], *W[indices[i]]);
    }
}

void Intersection::completeness_witness() {
    Utils utils;
    Ec1 g1 = pk->g1;
    xgcdTree();
    for (unsigned int i = 0; i < indices.size(); i++) {
        Ec1 digest1 = g1 * 0;
        polyS = q[indices[i]];
        int poly_size = polyS.rep.length();
        for (int j = 0; j < poly_size; j++) {
            const char *str = utils.zToString(polyS[j]);
            const mie::Vuint temp(str);
            free((char *) str);
            digest1 = digest1 + pk->pubs_g1[j] * temp;
        }
        (*Q[indices[i]]) = digest1;
        DEBUGINDEX("Completeness witness for ", indices[i], *Q[indices[i]]);
    }
}

Union::Union(const std::vector<int> indices, PublicKey *pk, DataStructure *dataStructure) {
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
    std::vector<QueryNode> tmp;
    tree.push_back(tmp);
    for (int i = 0; i < dataStructure->m; i++) {
        QueryNode tmp1;
        tree[0].push_back(tmp1);
        for (auto x:dataStructure->D[i]) {
            tree[0][i].SET.insert(x);
            tree[0].push_back(tmp1);
        }
    }
}

void Union::unionSets() {
    Utils utils;
    int len = dataStructure->m;
    int depth = 0;
    for (int i = 0; i < len; i++) {
        bn::Ec1 f1 = utils.compute_digest_pub(dataStructure->D[i], pk->g1, pk);
        bn::Ec2 f2 = utils.compute_digest_pub(dataStructure->D[i], pk->g2, pk);
        tree[depth][i].F1 = f1;
        tree[depth][i].F2 = f2;
    }
    while (len > 1) {
        depth++;
        std::vector<QueryNode> tmp;
        tree.push_back(tmp);
        if (len % 2 == 0) {
            for (int i = 0; i < len / 2; i++) {
                QueryNode tmpq;
                tree[depth].push_back(tmpq);
                setup_node(depth, i);
            }
        } else {
            log_err("Number of sets must be power of 2. It's %d", dataStructure->m);
        }
        len /= 2;
    }
}

void Union::setup_node(int depth, int length) {
    Utils utils;
    set_union(tree[depth - 1][length * 2].SET.begin(), tree[depth - 1][length * 2].SET.end(),
              tree[depth - 1][length * 2 + 1].SET.begin(), tree[depth - 1][length * 2 + 1].SET.end(),
              std::inserter(tree[depth][length].U, tree[depth][length].U.begin()), cmp);

    set_intersection(tree[depth - 1][length * 2].SET.begin(), tree[depth - 1][length * 2].SET.end(),
                     tree[depth - 1][length * 2 + 1].SET.begin(), tree[depth - 1][length * 2 + 1].SET.end(),
                     std::inserter(tree[depth][length].I, tree[depth][length].I.begin()), cmp);

    tree[depth][length].HU = utils.compute_digest_pub(tree[depth][length].U, pk->g2, pk);
    tree[depth][length].HUp = utils.compute_digest_puba(tree[depth][length].U, pk->g2, pk);
    tree[depth][length].HI = utils.compute_digest_pub(tree[depth][length].I, pk->g1, pk);
    tree[depth][length].HIp = utils.compute_digest_puba(tree[depth][length].I, pk->g2, pk);
    tree[depth][length].SET = tree[depth][length].U;

    tree[depth][length].F1 = utils.compute_digest_pub(tree[depth][length].SET, pk->g1, pk);
    tree[depth][length].F2 = tree[depth][length].HU;

    std::vector<NTL::ZZ_p> w1, w2;
    set_difference(tree[depth - 1][length * 2].SET.begin(), tree[depth - 1][length * 2].SET.end(),
                   tree[depth][length].I.begin(), tree[depth][length].I.end(), std::inserter(w1, w1.begin()), cmp);

    set_difference(tree[depth - 1][length * 2 + 1].SET.begin(), tree[depth - 1][length * 2 + 1].SET.end(),
                   tree[depth][length].I.begin(), tree[depth][length].I.end(), std::inserter(w2, w2.begin()), cmp);

    c.SetLength(w1.size());
    for (unsigned int j = 0; j < w1.size(); j++) {
        c[j] = -w1[j];
    }
    BuildFromRoots(p1, c);

    Ec2 digest = pk->g2 * 0;
    int size = p1.rep.length();
    for (int j = 0; j < size; j++) {
        const char *str = utils.zToString(p1[j]);
        mie::Vuint temp(str);
        free((char *) str);
        digest = digest + pk->pubs_g2[j] * temp;
    }
    tree[depth][length].W[0] = digest;

    c.SetLength(w2.size());
    for (unsigned int j = 0; j < w2.size(); j++) {
        c[j] = -w2[j];
    }
    BuildFromRoots(p2, c);

    digest = pk->g2 * 0;
    size = p2.rep.length();
    for (int j = 0; j < size; j++) {
        const char *str = utils.zToString(p2[j]);
        mie::Vuint temp(str);
        free((char *) str);
        digest = digest + pk->pubs_g2[j] * temp;
    }
    tree[depth][length].W[1] = digest;
    XGCD(PolyD, PolyS, PolyT, p1, p2);
    Ec1 digest1 = pk->g1 * 0;
    int poly_size = PolyS.rep.length();
    for (int j = 0; j < poly_size; j++) {
        const char *str = utils.zToString(PolyS[j]);
        const mie::Vuint temp(str);
        free((char *) str);
        digest1 = digest1 + pk->pubs_g1[j] * temp;
    }
    tree[depth][length].Q[0] = digest1;
    digest1 = pk->g1 * 0;
    poly_size = PolyT.rep.length();
    for (int j = 0; j < poly_size; j++) {
        const char *str = utils.zToString(PolyT[j]);
        const mie::Vuint temp(str);
        free((char *) str);
        digest1 = digest1 + pk->pubs_g1[j] * temp;
    }
    tree[depth][length].Q[1] = digest1;
}

Union2::Union2(const std::vector<int> indices, PublicKey *pk, DataStructure *dataStructure) {
    this->indices = indices;
    this->pk = pk;
    this->dataStructure = dataStructure;
    for (int i = 0; i < SETS_MAX_NO; i++)
        this->W2[i] = new bn::Ec2;
    for (int i = 0; i < SETS_MAX_SIZE; i++)
        this->W1[i] = new bn::Ec2;
}

Union2::~Union2() {
    for (int i = 0; i < SETS_MAX_SIZE; i++)
        delete (W1[i]);
    for (int i = 0; i < SETS_MAX_NO; i++)
        delete (W2[i]);
}


void Union2::unionSets() {
    std::set<NTL::ZZ_p, ZZ_p_compare> setsunion;
    debug("Union the sets %d and %d", indices[0], indices[1]);
    set_union(dataStructure->D[indices[0]].begin(), dataStructure->D[indices[0]].end(),
              dataStructure->D[indices[1]].begin(), dataStructure->D[indices[1]].end(),
              std::inserter(setsunion, setsunion.begin()), cmp);
    U = setsunion;
    for (unsigned int i = 2; i < indices.size(); i++) {
        set_union(dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(), U.begin(), U.end(),
                  std::inserter(setsunion, setsunion.begin()), cmp);
        U = setsunion;
        debug("Union the sets U and %d", indices[i]);
    }
}


void Union2::membership_witness() {
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator it;
    int idx = 0;
    for (it = U.begin(); it != U.end(); it++) {
        w.clear();
        std::vector<NTL::ZZ_p> tmp;
        tmp.push_back(*it);
        int superset = dataStructure->set_index[*it];
        set_indices.push_back(superset);
//        for (unsigned int j = 0; j < indices.size(); j++) {
//            if (dataStructure->D[indices[j]].find(*it) != dataStructure->D[indices[j]].end()) {
//                set_indices.push_back(j);
//                superset = indices[j];
//                break;
//            }
//        }
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
            char *str = utils.zToString(p[j]);
            mie::Vuint temp(str);
            free(str);
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W1[idx] = digest;
        idx++;
        DEBUGINDEX("Memberiship witness for ", idx, *W1[idx]);
    }
}

void Union2::superset_witness() {
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    for (unsigned int i = 0; i < indices.size(); i++) {
        w.clear();
        set_difference(U.begin(), U.end(), dataStructure->D[indices[i]].begin(), dataStructure->D[indices[i]].end(),
                       std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for (unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p, c);

        Ec2 digest = pk->g2 * 0;
        int size = p.rep.length();
        for (int j = 0; j < size; j++) {
            char *str = utils.zToString(p[j]);
            const mie::Vuint temp(str);
            free(str);
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W2[indices[i]] = digest;
        DEBUGINDEX("Superset witness for ", indices[i], *W2[indices[i]]);
    }
}

Subset::Subset(int I, int J, PublicKey *publicKey, DataStructure *dataStructure) {
    this->index[0] = I;
    this->index[1] = J;
    this->pk = publicKey;
    this->dataStructure = dataStructure;
    this->answer = 0;
    this->W = new bn::Ec2;
    for (int i = 0; i < 2; i++)
        this->Q[i] = new bn::Ec2;
}

Subset::~Subset() {
    delete W;
    for (int i = 0; i < 2; i++)
        delete Q[i];
}

void Subset::subset() {
    debug("Subet query: Is %d subset of %d?", index[1], index[0]);
    std::set<NTL::ZZ_p, ZZ_p_compare>::iterator first1, last1, first2, last2;
    first1 = dataStructure->D[index[0]].begin();
    last1 = dataStructure->D[index[0]].end();
    first2 = dataStructure->D[index[1]].begin();
    last2 = dataStructure->D[index[1]].end();
    while (first2 != last2) {
        if (first1 == last1 || cmp(*first2, *first1)) {
            answer = false;
            y = *first2;
            debug("%d is not subset of %d", index[1], index[0]);
            return;
        }
        if (!cmp(*first1, *first2))
            ++first2;
        ++first1;
    }
    answer = true;
    debug("%d is subset of %d", index[1], index[0]);
}

void Subset::positiveWitness() {
    if (!answer)
        return;
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    w.clear();
    set_difference(dataStructure->D[index[0]].begin(), dataStructure->D[index[0]].end(),
                   dataStructure->D[index[1]].begin(), dataStructure->D[index[1]].end(), std::inserter(w, w.begin()),
                   cmp);
    c.SetLength(w.size());
    for (unsigned int j = 0; j < w.size(); j++) {
        c[j] = -w[j];
    }
    BuildFromRoots(p[1], c);
    Ec2 digest = pk->g2 * 0;
    int size = p[1].rep.length();
    for (int j = 0; j < size; j++) {
        char *str = utils.zToString(p[1][j]);
        mie::Vuint temp(str);
        free(str);
        digest = digest + pk->pubs_g2[j] * temp;
    }
    *W = digest;
    DEBUG2INDEX("Subset witness for sets", index[0], index[1], *W);
}

void Subset::negativeWitness() {
    if (answer)
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
        char *str = utils.zToString(p[0][j]);
        mie::Vuint temp(str);
        free(str);
        digest = digest + pk->pubs_g2[j] * temp;
    }
    *W = digest;
    DEBUG("Membership Witness of y", *W);
    w.clear();
    for (auto p:dataStructure->D[index[0]])
        w.push_back(p);
    c.SetLength((w.size()));
    for (unsigned int j = 0; j < w.size(); j++) {
        c[j] = -w[j];
    }
    BuildFromRoots(p[0], c);

    tmp_c.SetLength(1);
    tmp_c[0] = -y;
    BuildFromRoots(p[1], tmp_c);
    XGCD(polyD, q[0], q[1], p[0], p[1]);
    for (int i = 0; i < 2; i++) {
        Ec2 digest1 = pk->g2 * 0;
        int poly_size = q[i].rep.length();
        for (int j = 0; j < poly_size; j++) {
            char *str = utils.zToString(q[i][j]);
            const mie::Vuint temp(str);
            free(str);
            digest1 = digest1 + pk->pubs_g2[j] * temp;
        }
        *Q[i] = digest1;
        DEBUGINDEX("(Subset Query) Completeness witness for set ", i, *Q[i]);
    }
}

Difference::Difference(int indices[], PublicKey *pk, DataStructure *dataStructure) {
    for (int i = 0; i < SMALL_QUERY_SIZE; i++)
        this->index[i] = indices[i];
    this->pk = pk;
    this->dataStructure = dataStructure;
    for (int i = 0; i < SMALL_QUERY_SIZE; i++)
        this->W[i] = new bn::Ec2;
    for (int i = 0; i < SMALL_QUERY_SIZE; i++)
        this->Q[i] = new bn::Ec1;
    this->digest_D = new bn::Ec1;
    this->Wd = new bn::Ec2;
    polyD = ZZ_pX(INIT_MONO, 0);
}

Difference::~Difference() {
    for (int i = 0; i < SMALL_QUERY_SIZE; i++) {
        if (W[i])
            delete W[i];
        if (Q[i])
            delete Q[i];
    }
    delete digest_D;
    delete Wd;
}

void Difference::difference() {
    debug("calculate difference of %d and %d", index[0], index[1]);
    set_difference(dataStructure->D[index[0]].begin(), dataStructure->D[index[0]].end(),
                   dataStructure->D[index[1]].begin(), dataStructure->D[index[1]].end(),
                   std::inserter(D, D.begin()), cmp);

    debug("difference size is %d", D.size());
    set_difference(dataStructure->D[index[0]].begin(), dataStructure->D[index[0]].end(),
                   D.begin(), D.end(),
                   std::inserter(I, I.begin()), cmp);
}

void Difference::witness() {
    Utils utils;
    std::vector<NTL::ZZ_p> w;
    for (auto p: I)
        w.push_back(p);
    c.SetLength(w.size());
    for (unsigned int j = 0; j < w.size(); j++) {
        c[j] = -w[j];
    }
    BuildFromRoots(p[0], c);

    Ec2 digest = pk->g2 * 0;
    int size = p[0].rep.length();
    for (int j = 0; j < size; j++) {
        char *str = utils.zToString(p[0][j]);
        mie::Vuint temp(str);
        free(str);
        digest = digest + pk->pubs_g2[j] * temp;
    }
    *Wd = digest;
    DEBUG("Witness of difference result", *Wd);
    for (int i = 0; i < SMALL_QUERY_SIZE; i++) {
        w.clear();
        set_difference(dataStructure->D[index[i]].begin(), dataStructure->D[index[i]].end(),
                       I.begin(), I.end(),
                       std::inserter(w, w.begin()), cmp);
        c.SetLength(w.size());
        for (unsigned int j = 0; j < w.size(); j++) {
            c[j] = -w[j];
        }
        BuildFromRoots(p[i], c);

        Ec2 digest = pk->g2 * 0;
        int size = p[i].rep.length();
        for (int j = 0; j < size; j++) {
            char *str = utils.zToString(p[i][j]);
            mie::Vuint temp(str);
            free(str);
            digest = digest + pk->pubs_g2[j] * temp;
        }
        *W[i] = digest;
        DEBUGINDEX("Membership witness of difference in ", i, *W[i]);
    }
    XGCD(polyD, q[0], q[1], p[0], p[1]);
    for (int i = 0; i < SMALL_QUERY_SIZE; i++) {
        Ec1 digest1 = pk->g1 * 0;
        int poly_size = q[i].rep.length();
        for (int j = 0; j < poly_size; j++) {
            char *str = utils.zToString(q[i][j]);
            const mie::Vuint temp(str);
            free(str);
            digest1 = digest1 + pk->pubs_g1[j] * temp;
        }
        *Q[i] = digest1;
        DEBUGINDEX("Completeness witness of difference in ", i, *Q[i]);
    }
}

