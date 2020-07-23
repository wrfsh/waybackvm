#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#if defined(CONFIG_TEST)

extern CU_pSuite g_suite;

typedef void(*wbvm_test_func_ptr)(void);

#if !defined(__GNUC__)
#   error Unsupported toolchain
#endif

#define TEST_SECTION     ".wbvm_test"
#define TEST_START       _wbvm_test_start
#define TEST_END         _wbvm_test_end

extern wbvm_test_func_ptr TEST_START[];
extern wbvm_test_func_ptr TEST_END[];

/* Declares a CUnit constructor function that registers a new test
 * and puts ctor pointer into special ELF section */
#define TEST_DECL_CTOR(func)                        \
    static void func(void);                         \
    static void func ##_ctor (void) {               \
        (void) CU_add_test(g_suite, #func, func);   \
    }                                               \
static wbvm_test_func_ptr func ##_ctor_fptr __attribute__((__section__(TEST_SECTION))) __attribute__((used)) = func ##_ctor

#else
#define TEST_DECL_CTOR(func)
#endif /* CONFIG_TEST */

#define WBVM_TEST(name)     \
    TEST_DECL_CTOR(name);   \
    WBVM_UNUSED static void name(void)
