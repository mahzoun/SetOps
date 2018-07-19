cmake_minimum_required(VERSION 3.10)
project(bilinear)

#g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pthread -march=native -Wall")

include_directories(
        ${CMAKE_SOURCE_DIR}/src/utils
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib
        ${CMAKE_SOURCE_DIR}/ate-pairing/src
        ${CMAKE_SOURCE_DIR}/xbyak
        ${CMAKE_SOURCE_DIR}/ate-pairing/include
        ${CMAKE_SOURCE_DIR}/ate-pairing/test
        ${CMAKE_SOURCE_DIR}/utils/
)

link_directories(
        ${CMAKE_SOURCE_DIR}/src/utils
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib
        ${CMAKE_SOURCE_DIR}/ate-pairing/src
        ${CMAKE_SOURCE_DIR}/xbyak
        ${CMAKE_SOURCE_DIR}/ate-pairing/include
        ${CMAKE_SOURCE_DIR}/ate-pairing/test
        ${CMAKE_SOURCE_DIR}/utils/
)

add_executable(
        bilinear
        src/main.cpp
        src/source/genkey.cpp
        src/source/genkey.h
        src/source/setup.cpp
        src/source/setup.h
        ${CMAKE_SOURCE_DIR}/ate-pairing/lib/libzm.a
        src/utils/utils.cpp src/utils/utils.h src/server/query.cpp src/server/query.h src/client/verify_intersection.cpp src/client/verify_intersection.h)

target_link_libraries(bilinear ntl gmp gmpxx m zm crypto)
