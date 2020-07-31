#pragma once

#include "wbvm/memory.h"
#include "wbvm/vcpu.h"

struct vdev;

struct vm
{
    /* x86 BSP vcpu */
    struct vcpu vcpu;

    /* Guest physical address space */
    struct address_space physical_address_space;

    /* System RAM memory region mapped to guest physical address space */
    struct memory_region ram;

    /* Mapped firmware image */
    struct memory_region firmware;

    /* KVM VM fd */
    int vmfd;

    /* Next free KVM memory slot */
    int next_slot;

    /* Emulated device list */
    LIST_HEAD(, vdev) devices;
};

int init_vm(struct vm* vm, gsize_t memsize, const char* fwpath);
int run_vm(struct vm* vm);
