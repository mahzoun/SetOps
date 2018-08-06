cmake_minimum_required(VERSION 3.10)

#g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm

project(main)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pthread -march=native -Wall")

include_directories(
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib
        ${CMAKE_SOURCE_DIR}/ate-pairing/src
        ${CMAKE_SOURCE_DIR}/xbyak
        ${CMAKE_SOURCE_DIR}/ate-pairing/include
        ${CMAKE_SOURCE_DIR}/ate-pairing/test
        ${CMAKE_SOURCE_DIR}/lib
        ${CMAKE_SOURCE_DIR}/googletest/
        ${CMAKE_SOURCE_DIR}/googletest/googletest/include
        ${CMAKE_SOURCE_DIR}/googletest/googlemock/include
)

link_directories(
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib
        ${CMAKE_SOURCE_DIR}/ate-pairing/src
        ${CMAKE_SOURCE_DIR}/xbyak
        ${CMAKE_SOURCE_DIR}/ate-pairing/include
        ${CMAKE_SOURCE_DIR}/ate-pairing/test
        ${CMAKE_SOURCE_DIR}/lib
        ${CMAKE_SOURCE_DIR}/googletest/googletest/include
        ${CMAKE_SOURCE_DIR}/googletest/googlemock/include
)

add_executable(
        bilinear
        main.cpp
        source/genkey.cpp
        ${CMAKE_SOURCE_DIR}/lib/source/genkey.h
        source/setup.cpp
        ${CMAKE_SOURCE_DIR}/lib/source/setup.h
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib/libzm.a
        utils/utils.cpp
        ${CMAKE_SOURCE_DIR}/lib/utils/utils.h
        server/query.cpp
        ${CMAKE_SOURCE_DIR}/lib/server/query.h
        client/verify_intersection.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_intersection.h
        ${CMAKE_SOURCE_DIR}/lib/utils/dbg.h
        ${CMAKE_SOURCE_DIR}/lib/utils/merkletree.h
        utils/merkletree.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_tree.h
        client/verify_tree.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_union.h
        client/verify_union.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_subset.h
        client/verify_subset.cpp
)



target_link_libraries(bilinear ntl gmp gmpxx m zm crypto)

set(
        SRC
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib/libzm.a
        source/genkey.cpp
        ${CMAKE_SOURCE_DIR}/lib/source/genkey.h
        source/setup.cpp
        ${CMAKE_SOURCE_DIR}/lib/source/setup.h
        utils/merkletree.cpp
        ${CMAKE_SOURCE_DIR}/lib/utils/merkletree.h
        source/setup.cpp
        ${CMAKE_SOURCE_DIR}/lib/source/setup.h
        server/query.cpp
        ${CMAKE_SOURCE_DIR}/lib/server/query.h
        client/verify_tree.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_tree.h
        client/verify_intersection.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_intersection.h
        client/verify_union.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_union.h
        client/verify_subset.cpp
        ${CMAKE_SOURCE_DIR}/lib/client/verify_subset.h
)

add_library(utils STATIC ${CMAKE_SOURCE_DIR}/lib/utils/utils.h utils/utils.cpp)
target_link_libraries(utils ntl m zm gmp gmpxx ssl crypto)

add_library(setops STATIC ${SRC})
target_link_libraries(setops ntl gmp gmpxx m zm utils)
target_include_directories(setops PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

