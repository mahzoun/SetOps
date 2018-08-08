//
// Created by sauron on 7/20/18.

#ifndef __dbg_h__
#define __dbg_h__

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <iostream>
using namespace std;

#ifdef NODEBUG
#define debug(M, ...)
#define DEBUGINDEX(M, i, V)
#define DEBUG2INDEX(M, i, j, V)
#else
#define debug(M, ...) fprintf(stderr, "[DEBUG] %s:%d: " M "\n", __FILE__, \
        __LINE__,  ##__VA_ARGS__)
#define DEBUG(M, V) cerr << "DEBUG :" << __FILE__ << ":" << __LINE__ << M << "\t" << V << endl;
#define DEBUGINDEX(M, i, V) cerr << "[DEBUG] " << __FILE__ << ":" << __LINE__ <<": " << M << "\t" << i << "\t" << V << endl;
#define DEBUG2INDEX(M, i, j, V) cerr << "[DEBUG] " << __FILE__ << ":" << __LINE__ <<": " << M << "\t" << i <<"\t" << j << "\t" << V << endl;
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr, "[ERROR] (%s:%d: errno: %s) " M "\n", \
        __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...) fprintf(stderr, "[WARN] (%s:%d: errno: %s) " M "\n", \
        __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_info(M, ...) fprintf(stdout, "[INFO] (%s:%d:) " M "\n", \
        __FILE__, __LINE__, ##__VA_ARGS__)

#define check(A, M, ...) if(!(A)) { log_err(M, ##__VA_ARGS__); errno=0; goto \
        error; }

#define sentinel(M, ...) { log_err(M, ##__VA_ARGS__); errno=0; goto error; }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...) if(!(A)) {debug(M, ##__VA_ARGS__); errno=0; \
    goto error;}

#endif
