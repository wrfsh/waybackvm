#include "wbvm/kvm.h"
#include "wbvm/platform.h"

#include <sys/ioctl.h>

#define MIN_KVM_VERSION 12

static int g_kvmfd = -1;
static int g_max_vcpus;

int kvm_ioctl(unsigned long request, uintptr_t arg)
{
    int ret = ioctl(g_kvmfd, request, arg);
    if (ret < 0) {
        WBVM_LOG_ERROR2(ret, "KVM ioctl %lu failed", request);
        return -errno;
    }

    return ret;
}

int kvm_ioctl_nofail(unsigned long request, uintptr_t arg)
{
    int ret = kvm_ioctl(request, arg);
    WBVM_VERIFY(ret >= 0);
    return ret;
}

int kvm_vm_ioctl(int vmfd, unsigned long request, uintptr_t arg)
{
    int ret = ioctl(vmfd, request, arg);
    if (ret < 0) {
        return -errno;
    }

    return ret;
}

int kvm_vm_ioctl_nofail(int vmfd, unsigned long request, uintptr_t arg)
{
    int ret = kvm_vm_ioctl(vmfd, request, arg);
    WBVM_VERIFY(ret >= 0);
    return ret;
}

int kvm_vcpu_ioctl(int vcpufd, unsigned long request, uintptr_t arg)
{
    int ret = ioctl(vcpufd, request, arg);
    if (ret < 0) {
        WBVM_LOG_ERROR2(ret, "KVM VCPU request %#lx failed", request);
        return -errno;
    }

    return ret;
}

int kvm_vcpu_ioctl_nofail(int vcpufd, unsigned long request, uintptr_t arg)
{
    int ret = kvm_vcpu_ioctl(vcpufd, request, arg);
    WBVM_VERIFY(ret >= 0);
    return ret;
}

int kvm_init(void)
{
    int res = 0;

    res = open("/dev/kvm", O_RDONLY);
    if (res < 0) {
        WBVM_LOG_ERROR("Could not open /dev/kvm: %d", errno);
        return res;
    }

    g_kvmfd = res;

    res = kvm_ioctl(KVM_GET_API_VERSION, 0);
    if (res < 0) {
        WBVM_LOG_ERROR("Cloud not get KVM version: %d", res);
    }

    WBVM_LOG_DEBUG("KVM API version: %d", res);
    if (res < MIN_KVM_VERSION) {
        WBVM_LOG_ERROR("Bad KVM version");
        return -ENOTSUP;
    }

    res = kvm_ioctl(KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
    if (res < 0) {
        WBVM_LOG_ERROR("Could not get NR_VCPUS: %d", res);
        return res;
    }

    g_max_vcpus = res;
    return 0;
}
