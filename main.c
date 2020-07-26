#include "wbvm/platform.h"
#include "wbvm/kvm.h"
#include "wbvm/vm.h"

#define VM_MEMSIZE ((gsize_t)1 << 27) /* 128MB */

static struct vm vm;

int main(int argc, char** argv)
{
    int res = 0;

    res = kvm_init();
    if (res != 0) {
        WBVM_DIE("failed to init KVM");
    }

    res = init_vm(&vm, VM_MEMSIZE);
    if (res != 0) {
        WBVM_DIE("failed to init vm");
    }

    do { } while (1);
    return EXIT_SUCCESS;
}
