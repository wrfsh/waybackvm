#pragma once

#include <inttypes.h>
#include <linux/kvm.h>

int kvm_ioctl(unsigned long request, uintptr_t arg);
int kvm_ioctl_nofail(unsigned long request, uintptr_t arg);

int kvm_vm_ioctl(int vmfd, unsigned long request, uintptr_t arg);
int kvm_vm_ioctl_nofail(int vmfd, unsigned long request, uintptr_t arg);

int kvm_vcpu_ioctl(int vcpufd, unsigned long request, uintptr_t arg);
int kvm_vcpu_ioctl_nofail(int vcpufd, unsigned long request, uintptr_t arg);

int kvm_init(void);
