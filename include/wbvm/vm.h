#pragma once

#include "wbvm/x86.h"

struct vcpu
{
    struct x86_cpu_state x86_cpu;
    struct vm* vm;
    uint32_t id;
    unsigned long mmap_size;
    pthread_t tid;

    /* KVM-specific state */
    struct kvm_run* kvm_run;
    int vcpufd;
};

struct vm
{
    /* x86 BSP vcpu */
    struct vcpu vcpu;

    /* Physical memory region mapping */
    void* physical_memory;
    uint64_t memsize;

    /* KVM VM fd */
    int vmfd;

    enum {
        KVM_MEMSLOT_SYSTEM_MEMORY = 0, /** KVM memslot for physical system memory */
    };
};

int init_vm(struct vm* vm, uint64_t memsize);
