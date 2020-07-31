#pragma once

#include "wbvm/x86.h"

enum vcpu_state
{
    VCPU_STOPPED = 0,
    VCPU_PAUSED,
    VCPU_RUNNING,
    VCPU_TERMINATED,
};

struct vcpu
{
    /* Unbderlying x86 state */
    struct x86_cpu_state x86_cpu;

    /* Owning VM */
    struct vm* vm;

    /* VCPU id, doubles as apic id */
    uint32_t id;

    /* VCPU state */
    enum vcpu_state state;

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

/**
 * Send a signal to vcpu to either lick it into userspace or notify of a state change.
 */
void vcpu_kick(struct vcpu* vcpu);

/**
 * Run vcpu that is currently stopped or paused
 */
void vcpu_run(struct vcpu* vcpu);
