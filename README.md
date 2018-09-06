# setops
 SetOps is a C++ library which allowing a data owner to outsource set operations on a collection of sets to an untrusted server where the correctness of operations can be verified publicly.
 
## Authors.

[Dimitrios Papadopoulos](https://www.cse.ust.hk/~dipapado/) <br>
[Mohammad Mahzoun](http://mahzoun.me/)

## Build instruction
SetOps use following libraries to run:
1. openssl
2. [ate-paring](https://github.com/herumi/ate-pairing)
3. [xbyak](https://github.com/herumi/xbyak)
4. [NTL](http://www.shoup.net/ntl/doc/tour.html)
5. [gmp](https://gmplib.org/manual/C_002b_002b-Interface-General.html)



Download and install 2 and 3 from above list in the same directory as SetOps.
<br>
* To compile SetOps, do as follow:<br>
```cmake CmakeLists.txt```

* Run tests: <br>
```make tests```

TODO: Add API documentation.

### License
[Apache License 2.0](https://github.com/mahzoun/setops/blob/master/LICENSE)