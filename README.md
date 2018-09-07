# SetOps
## Overview
SetOps is a C++ library which allows a data owner to outsource set operations on a collection of sets to an untrusted server where the correctness of operations can be verified publicly based on the algorithms described [1](https://eprint.iacr.org/2013/724.pdf) and [2](https://eprint.iacr.org/2010/455.pdf).
SetOps library consists of three main components, a
source which owns set collection, a server which handles
queries on the sets and clients which are interested to query operations and verify the
answer without accessing to any secret data. SetOps supports primitive set operations
like intersection, union, subset and set difference on large sets and benefits the small proof
size and fast verification time, both of which depends only on the number of sets. The security
of the system relies on known cryptographic assumptions such as bilinear q-strong Diffie-
Hellman.

## Build instruction
SetOps uses following libraries to run:
1. [openssl](https://www.openssl.org/)
2. [ate-paring](https://github.com/herumi/ate-pairing)
3. [xbyak](https://github.com/herumi/xbyak)
4. [NTL](http://www.shoup.net/ntl/doc/tour.html)
5. [gmp](https://gmplib.org/manual/C_002b_002b-Interface-General.html)


Note: 2 and 3 from above list should be placed in the same directory as SetOps.
<br>
* To compile SetOps, do as follow:<br>
```cmake CmakeLists.txt```

* Run tests: <br>
```make tests```

## Usage
Generate keys:
```cpp
NTL::ZZ p = NTL::conv<NTL::ZZ>("16798108731015832284940804142231733909759579603404752749028378864165570215949");
NTL::ZZ_p::init(p);
Key *k = new Key(p); 
//k->sk is secret key and k->pk is public key
```

Create the data structure:
```cpp
DataStructure *dataStructure = new DataStructure(SETS_NO, k);
// SETS_NO is number of sets and k is the key
```
After creating a datastructure, a collection of `SETS_NO` sets will be created. Elements can be inserted to sets as follow:
```cpp
dataStructure->insert(i, j, pk, sk);
// The NTL::ZZ_p j will be inserted to set i. pk and sk are public key and secret key
```

### Intersection
To query the intersection of sets, a client should do as follow:
```cpp
Intersection *intersection = new Intersection(indices, pk, dataStructure);
intersection->intersect();
intersection->subset_witness();
intersection->completeness_witness();
```
The intersection result will be `intersection->I`.
The client can verify the result as follow:
```cpp
VerifyTree *verifyTree = new VerifyTree;
verifyTree->verifyTree(pk, dataStructure, indices);
VerifyIntersection *verifyIntersection = new VerifyIntersection(intersection->I, intersection->W, intersection->Q,
                                                                dataStructure->AuthD, dataStructure->m, incdices);
bool b = verifyIntersection->verify_intersection();
```
<br>

### Union
The SetOps supports two types of union query, the first one is by [1](https://eprint.iacr.org/2013/724.pdf) and fast. It
works as follow:
```cpp
Union *un = new Union(indices, pk, dataStructure);
un->unionSets();
```
The union is `un->U` and the verification is as follow:
```cpp
VerifyTree *verifyTree = new VerifyTree;
verifyTree->verifyTree(pk, dataStructure, indices);
VerifyUnion *verifyUnion = new VerifyUnion(pk, un->U, un->tree, dataStructure->m, un->set_indices);
bool b = verifyUnion->verify_union();
```
Second union method by [2](https://eprint.iacr.org/2010/455.pdf) works as follow:
```cpp
Union2 *un = new Union2(indices, pk, dataStructure);
un->unionSets();
un->membership_witness();
un->superset_witness();
```
The verification of the above query is as follow:
```cpp
VerifyTree *verifyTree = new VerifyTree;
verifyTree->verifyTree(pk, dataStructure, indices);
VerifyUnion2 *verifyUnion = new VerifyUnion2(pk, un->U, un->W1, un->W2, dataStructure->AuthD,
                                           dataStructure->m, v, un->set_indices);
verifyUnion->verify_union;
```

### Subset and Set Difference
You can find examples of these query usages in `main.cpp`
## Authors

[Dimitrios Papadopoulos](https://www.cse.ust.hk/~dipapado/) <br>
[Mohammad Mahzoun](http://mahzoun.me/)

## References
[1] R. Canetti, O. Paneth, D. Papadopoulos, and N. Triandopoulos, “Verifiable set operations over
outsourced databases,” IACR Cryptology ePrint Archive, vol. 2013, p. 724, 2013.

[2] C. Papamanthou, R. Tamassia, and N. Triandopoulos, “Optimal verification of operations on
    dynamic sets,” IACR Cryptology ePrint Archive, vol. 2010, p. 455, 2010.
   

## License
[Apache License 2.0](https://github.com/mahzoun/setops/blob/master/LICENSE)