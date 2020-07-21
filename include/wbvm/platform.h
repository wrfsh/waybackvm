#pragma once

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

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

static inline void* wbvm_malloc(size_t size)
{
    void* res = malloc(size);
    WBVM_VERIFY(res);
    return res;
}

static inline void* wbvm_zalloc(size_t size)
{
    void* res = wbvm_malloc(size);
    memset(res, 0, sizeof(*res));
    return res;
}

static inline void* wbvm_calloc(size_t nmemb, size_t size)
{
    void* res = calloc(nmemb, size);
    WBVM_VERIFY(res);
    return res;
}

static inline void wbvm_free(void* p)
{
    if (p) {
        free(p);
    }
}