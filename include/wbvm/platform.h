#pragma once

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#if !defined(__GNUC__)
#   error Unsupported toolchain
#endif

#ifdef _DEBUG
#   define WBVM_LOG_DEBUG(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);
#   define WBVM_ASSERT(pred) assert(pred)
#else
#   define WBVM_LOG_DEBUG(fmt, ...)
#   define WBVM_ASSERT(pred)
#endif

#define WBVM_LOG_ERROR(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define WBVM_LOG_ERROR2(code, fmt, ...) fprintf(stderr, "%s:%d: " fmt ": %d\n", __FUNCTION__, __LINE__, ##__VA_ARGS__, (code));

#define WBVM_VERIFY(pred) assert(pred)
#define WBVM_DIE(fmt, ...) do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); exit(EXIT_FAILURE); } while (0);

#define WBVM_UNUSED     __attribute__((unused))
#define WBVM_CTOR       __attribute__((constructor))

#define WBVM_MIN(a, b) ((a) < (b) ? (a) : (b))
#define WBVM_MAX(a, b) ((a) > (b) ? (a) : (b))

#define offset_of(type, member)  __builtin_offsetof (type, member)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offset_of(type, member) );})

static inline void* wbvm_alloc(size_t size)
{
    void* res = malloc(size);
    WBVM_VERIFY(res);
    return res;
}

static inline void* wbvm_zalloc(size_t size)
{
    void* res = wbvm_alloc(size);
    memset(res, 0, sizeof(*res));
    return res;
}

static inline void* wbvm_calloc(size_t nmemb, size_t size)
{
    void* res = calloc(nmemb, size);
    WBVM_VERIFY(res);
    return res;
}

static inline void* wbvm_realloc(void* ptr, size_t new_size)
{
    void* res = realloc(ptr, new_size);
    WBVM_VERIFY(res);
    return res;
}

static inline void wbvm_free(void* p)
{
    if (p) {
        free(p);
    }
}
