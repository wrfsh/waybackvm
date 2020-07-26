#include "wbvm/platform.h"
#include "wbvm/kvm.h"
#include "wbvm/vm.h"

#include <sys/mman.h>
#include <pthread.h>

/** Set x86 general purpose registers for KVM */
static void kvm_set_regs(const struct vcpu* vcpu)
{
    const struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;
    struct kvm_regs kvmregs;

    kvmregs.rax = x86_cpu->eax;
    kvmregs.rbx = x86_cpu->ebx;
    kvmregs.rcx = x86_cpu->ecx;
    kvmregs.rdx = x86_cpu->edx;
    kvmregs.rsi = x86_cpu->esi;
    kvmregs.rdi = x86_cpu->edi;
    kvmregs.rsp = x86_cpu->esp;
    kvmregs.rbp = x86_cpu->ebp;
    kvmregs.rip = x86_cpu->eip;
    kvmregs.rflags = x86_cpu->eflags;

    kvm_vcpu_ioctl_nofail(vcpu->vcpufd, KVM_SET_REGS, (uintptr_t)&kvmregs);
}

/** Set x86 segment descriptor values for KVM */
static void kvm_set_seg(struct kvm_segment* kvmseg, const struct x86_segment* seg)
{
    kvmseg->base = seg->base;
    kvmseg->limit = seg->limit;
    kvmseg->selector = seg->selector;
    kvmseg->type = seg->type;
    kvmseg->dpl = seg->dpl;
    kvmseg->present = !!(seg->flags & X86_SEG_P);
    kvmseg->db = !!(seg->flags & X86_SEG_DB);
    kvmseg->s = !!(seg->flags & X86_SEG_S);
    kvmseg->l = !!(seg->flags & X86_SEG_L);
    kvmseg->g = !!(seg->flags & X86_SEG_G);
    kvmseg->avl = !!(seg->flags & X86_SEG_AVL);
    kvmseg->unusable = !kvmseg->present;
}

/** Set x86 system registers for KVM */
static void kvm_set_sregs(const struct vcpu* vcpu)
{
    const struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;
    struct kvm_sregs kvm_sregs = {0};

    kvm_set_seg(&kvm_sregs.cs, &x86_cpu->cs);
    kvm_set_seg(&kvm_sregs.ds, &x86_cpu->ds);
    kvm_set_seg(&kvm_sregs.es, &x86_cpu->es);
    kvm_set_seg(&kvm_sregs.fs, &x86_cpu->fs);
    kvm_set_seg(&kvm_sregs.gs, &x86_cpu->gs);
    kvm_set_seg(&kvm_sregs.ss, &x86_cpu->ss);
    kvm_set_seg(&kvm_sregs.tr, &x86_cpu->tr);
    kvm_set_seg(&kvm_sregs.ldt, &x86_cpu->ldt);

    kvm_sregs.cr0 = x86_cpu->cr0;
    kvm_sregs.cr2 = x86_cpu->cr2;
    kvm_sregs.cr3 = x86_cpu->cr3;
    kvm_sregs.cr4 = x86_cpu->cr4;

    kvm_sregs.efer = x86_cpu->efer;

    kvm_vcpu_ioctl_nofail(vcpu->vcpufd, KVM_SET_SREGS, (uintptr_t)&kvm_sregs);
}

static void* vcpu_thread(void* arg)
{
    int res = 0;
    bool should_exit = false;
    struct vcpu* vcpu = (struct vcpu*) arg;
    WBVM_ASSERT(vcpu);

    WBVM_LOG_DEBUG("running vcpu %d", vcpu->id);

    do {
        res = kvm_vcpu_ioctl(vcpu->vcpufd, KVM_RUN, 0);
        if (res != 0) {
            WBVM_LOG_ERROR2(res, "KVM_RUN failed");

            /* TODO: parking? */
            break;
        }

        WBVM_LOG_DEBUG("vcpu %d exited, reason 0x%x", vcpu->id, vcpu->kvm_run->exit_reason);

    } while (!should_exit);

    return NULL;
}

static int init_vcpu(struct vm* vm, struct vcpu* vcpu, uint32_t id)
{
    int res = 0;
    void* mmap_ptr = NULL;
    unsigned long mmap_size = kvm_ioctl_nofail(KVM_GET_VCPU_MMAP_SIZE, 0);

    memset(vcpu, 0, sizeof(*vcpu));

    vcpu->vcpufd = kvm_vm_ioctl_nofail(vm->vmfd, KVM_CREATE_VCPU, id);

    mmap_ptr = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, vcpu->vcpufd, 0);
    if (mmap_ptr == MAP_FAILED) {
        WBVM_LOG_ERROR2(-errno, "vcpu mmap failed");
        return -errno;
    }

    vcpu->mmap_size = mmap_size;
    vcpu->kvm_run = (struct kvm_run*) mmap_ptr;
    vcpu->vm = vm;

    reset_x86_bsp(&vcpu->x86_cpu);

    kvm_set_regs(vcpu);
    kvm_set_sregs(vcpu);

    res = pthread_create(&vcpu->tid, NULL, vcpu_thread, vcpu);
    if (res != 0) {
        WBVM_LOG_ERROR2(res, "failed to create vcpu thread");
        return res;
    }

    return 0;
}

static int init_memory(struct vm* vm, uint64_t memsize)
{
    vm->physical_memory = mmap(NULL, memsize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (vm->physical_memory == MAP_FAILED) {
        WBVM_LOG_ERROR2(-errno, "physical memory mmap failed");
        return -1;
    }

    struct kvm_userspace_memory_region memregion;
    memregion.slot = KVM_MEMSLOT_SYSTEM_MEMORY;
    memregion.flags = 0;
    memregion.guest_phys_addr = 0;
    memregion.memory_size = memsize;
    memregion.userspace_addr = (uintptr_t)vm->physical_memory;

    kvm_vm_ioctl_nofail(vm->vmfd, KVM_SET_USER_MEMORY_REGION, (uintptr_t)&memregion);
    return 0;
}

int init_vm(struct vm* vm, uint64_t memsize)
{
    int res = 0;

    memset(vm, 0, sizeof(*vm));

    vm->vmfd = kvm_ioctl(KVM_CREATE_VM, 0);
    if (vm->vmfd < 0) {
        WBVM_LOG_ERROR2(res, "could not create VM");
        return res;
    }

    res = init_memory(vm, memsize);
    if (res != 0) {
        return res;
    }

    res = init_vcpu(vm, &vm->vcpu, 0);
    if (res != 0) {
        return res;
    }

    return 0;
}
