/**
 * @Author: S. Sharma <silentcat>
 * @Date:   2019-05-17T21:06:54-05:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-01-24T21:32:31-06:00
 */

#ifndef __dbg_h__
#define __dbg_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", \
        __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr,\
        "[WARN] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__,\
        clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...) fprintf(stderr,\
        "[WARN] (%s:%d: errno: %s) " M "\n",\
        __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_info(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n",\
        __FILE__, __LINE__, ##__VA_ARGS__)

#define check(A, M, ...) if (!(A)) {\
    log_err(M, ##__VA_ARGS__); errno = 0; goto error; }

#define check_no_out(A, ...) if (!(A)) { errno = 0; goto error; }


#define sentinel(M, ...) { log_err(M, ##__VA_ARGS__);\
    errno=0; goto error; }

#define check_mem(A) check((A), "Out of memory.");

#define check_debug(A, M, ...) if (!(A)) { debug(M, ##__VA_ARGS__);\
    errno=0; goto error; }

#define time_func(A, ...) start = clock(); (A)(__VA_ARGS__); end = clock(); \
    tm = ((end - start) / (double)CLOCKS_PER_SEC);

#endif
