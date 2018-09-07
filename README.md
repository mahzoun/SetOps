# SetOps
##Overview
SetOps is a C++ library which allows a data owner to outsource set operations on a collection of sets to an untrusted server where the correctness of operations can be verified publicly based on the algorithms described [1](https://eprint.iacr.org/2013/724.pdf) and [2](https://eprint.iacr.org/2010/455.pdf).
SetOps library consists of three main components, a
source which owns a dynamic sets of a specified domain, a powerful server which handles
queries on the sets and clients which are interested to query operations and verify the
answer without accessing to any secret data. SetOps supports primitive set operations
like intersection, union, subset and set difference on large sets and benefits the small proof
size and fast verification time, both of which depends only on the number of sets. These
operations are building blocks of more complicated systems. In fact, the primitive set
queries can extend to handle database queries or many other applications. The security
of the system relies on known cryptographic assumptions such as bilinear q-strong Diffie-
Hellman.

## Build instruction
SetOps use following libraries to run:
1. openssl
2. [ate-paring](https://github.com/herumi/ate-pairing)
3. [xbyak](https://github.com/herumi/xbyak)
4. [NTL](http://www.shoup.net/ntl/doc/tour.html)
5. [gmp](https://gmplib.org/manual/C_002b_002b-Interface-General.html)


Note: 2 and 3 from above list should be in the same directory as SetOps.
<br>
* To compile SetOps, do as follow:<br>
```cmake CmakeLists.txt```

* Run tests: <br>
```make tests```

##Usage

TODO: Add API documentation.

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