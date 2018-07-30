cmake_minimum_required(VERSION 3.10)

#g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pthread -march=native -Wall")

include_directories(
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib
        ${CMAKE_SOURCE_DIR}/ate-pairing/src
        ${CMAKE_SOURCE_DIR}/xbyak
        ${CMAKE_SOURCE_DIR}/ate-pairing/include
        ${CMAKE_SOURCE_DIR}/ate-pairing/test
        ${CMAKE_SOURCE_DIR}/lib
        ${CMAKE_SOURCE_DIR}/lib/source
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
        ${CMAKE_SOURCE_DIR}/lib/source
        ${CMAKE_SOURCE_DIR}/googletest/googletest/include
        ${CMAKE_SOURCE_DIR}/googletest/googlemock/include
)


ADD_EXECUTABLE(
        tests
        test.cpp
        Intersection.cpp
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib/libzm.a
)

TARGET_LINK_LIBRARIES(tests libgtest libgmock ntl gmp gmpxx m zm crypto setops)

add_test(NAME tests
        COMMAND tests)
