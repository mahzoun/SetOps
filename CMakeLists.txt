cmake_minimum_required(VERSION 3.10)
project(bilinear)

#g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pthread -march=native -Wall")
add_subdirectory(googletest)

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
        src/main.cpp
        src/source/genkey.cpp
        lib/source/genkey.h
        src/source/setup.cpp
        lib/source/setup.h
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib/libzm.a
        src/utils/utils.cpp
        lib/utils/utils.h
        src/server/query.cpp
        lib/server/query.h
        src/client/verify_intersection.cpp
        lib/client/verify_intersection.h
        lib/utils/dbg.h
        lib/utils/merkletree.h
        src/utils/merkletree.cpp
        lib/client/verify_tree.h
        src/client/verify_tree.cpp
)



target_link_libraries(bilinear ntl gmp gmpxx m zm crypto gtest gtest_main gmock gmock_main)


#Define your executable
add_executable(Test test/test.cpp)

#Link with GoogleTest
target_link_libraries(Test gtest gtest_main)

#Link with GoogleMock
target_link_libraries(Test gmock gmock_main)
