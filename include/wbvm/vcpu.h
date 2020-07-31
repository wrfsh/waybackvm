#pragma once

#include "wbvm/x86.h"

struct vcpu
{
    /* Unbderlying x86 state */
    struct x86_cpu_state x86_cpu;

    /* Owning VM */
    struct vm* vm;

    /* VCPU id, doubles as apic id */
    uint32_t id;

    /* KVM file descriptor */
    int vcpufd;

    /* Size of mmaped kvm_run buffer */
    unsigned long mmap_size;

    /* KVM-specific state */
    volatile struct kvm_run* kvm_run;

    /* VCPU execution thread */
    pthread_t tid;
};

int init_vcpu(struct vm* vm, struct vcpu* vcpu, uint32_t id);
