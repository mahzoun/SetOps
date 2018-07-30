cmake_minimum_required(VERSION 3.10)

#g++ -g -O2 -std=c++11 -pthread -march=native foo.cpp -o foo -lntl -lgmp -lm


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pthread -march=native -Wall")

file(GLOB SRCS *.cpp)

ADD_EXECUTABLE(tests ${SRCS})

TARGET_LINK_LIBRARIES(tests libgtest libgmock)

add_test(NAME tests
        COMMAND tests)
