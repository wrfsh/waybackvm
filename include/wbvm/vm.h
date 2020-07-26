#pragma once

#include "wbvm/x86.h"
#include "wbvm/memory.h"

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

    /* Guest physical address space */
    struct address_space physical_address_space;

    /* System RAM memory region mapped to guest physical address space */
    struct memory_region ram;

    /* KVM VM fd */
    int vmfd;

    /* Next free KVM memory slot */
    int next_slot;
};

int init_vm(struct vm* vm, gsize_t memsize);
