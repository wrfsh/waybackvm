#include <wbvm/test.h>

CU_pSuite g_suite = NULL;

/**
 * Entry point for unit test build
 */
int main(int argc, char** argv)
{
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    g_suite = CU_add_suite("test suite", NULL, NULL);
    if (NULL == g_suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* run test constructors */
    wbvm_test_func_ptr* t = _wbvm_test_start;
    while (t != _wbvm_test_end) {
        (*t++)();
    }

    /* run tests */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    int res = CU_get_error() || CU_get_number_of_tests_failed();

    CU_cleanup_registry();
    g_suite = NULL;

    return res;
}
