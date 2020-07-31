#include "wbvm/platform.h"
#include "wbvm/kvm.h"
#include "wbvm/vm.h"

#define VM_MEMSIZE ((gsize_t)1 << 27) /* 128MB */
#define FW_IMAGE_PATH "build-x86/bios.bin"

static struct vm vm;

int main(int argc, char** argv)
{
    int res = 0;

    res = kvm_init();
    if (res != 0) {
        WBVM_DIE("failed to init KVM");
    }

    res = init_vm(&vm, VM_MEMSIZE, FW_IMAGE_PATH);
    if (res != 0) {
        WBVM_DIE("failed to init vm");
    }

    return run_vm(&vm);
}
