#include "wbvm/platform.h"
#include "wbvm/kvm.h"

#include <stdbool.h>
#include <sys/mman.h>

#include <pthread.h>

#define VM_MEMSIZE (1ull << 27) /* 128MB */

struct x86_segment
{
    uint32_t base;
    uint16_t limit;
    uint16_t selector;
    uint8_t dpl;

    enum {
        X86_SEG_TYPE_RW  = (1 << 1),
        X86_SEG_TYPE_ACCESSED = (1 << 0),
    };
    uint8_t type;

    enum {
        X86_SEG_S   = (1 << 0),
        X86_SEG_P   = (1 << 1),
        X86_SEG_AVL = (1 << 2),
        X86_SEG_L   = (1 << 3),
        X86_SEG_DB  = (1 << 4),
        X86_SEG_G   = (1 << 5),
    };
    uint8_t flags;
};

struct x86_dtbl
{
    uint32_t base;
    uint16_t limit;
};

struct x86_cpu_state
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi, esp, ebp;

    uint32_t eflags;
    uint32_t eip;

    struct x86_segment cs;
    struct x86_segment ds;
    struct x86_segment es;
    struct x86_segment fs;
    struct x86_segment gs;
    struct x86_segment ss;
    struct x86_segment tr;
    struct x86_segment ldt;

    struct x86_dtbl gdt, idt;

    uint32_t cr0, cr2, cr3, cr4;
    uint32_t efer;
    uint32_t apic_base;
};

struct kvm_vcpu
{
    struct x86_cpu_state x86_cpu;
    struct kvm_vm* vm;
    uint32_t id;
    unsigned long mmap_size;
    pthread_t tid;

    /* KVM-specific state */
    struct kvm_run* kvm_run;
    int vcpufd;
};

/**
 * KVM-specific VM state
 */
struct kvm_vm
{
    /* x86 BSP vcpu */
    struct kvm_vcpu vcpu;

    /* Physical memory region mapping */
    void* physical_memory;
    uint64_t memsize;

    /* KVM VM fd */
    int vmfd;

    enum {
        KVM_MEMSLOT_SYSTEM_MEMORY = 0, /** KVM memslot for physical system memory */
    };
};

/** Reset x86 segment to default state */
static void reset_x86_segment(struct x86_segment* seg, uint8_t type)
{
    seg->base = 0;
    seg->limit = 0xFFFF;
    seg->selector = 0;
    seg->type = type;
    seg->dpl = 0;
    seg->flags = X86_SEG_P;
}

/** Reset x86 descriptor table register to default state */
static void reset_x86_dtbl(struct x86_dtbl* dtbl)
{
    dtbl->base = 0;
    dtbl->limit = 0xFFFF;
}

/** Reset x86 boot processor */
static void reset_x86_bsp(struct kvm_vcpu* vcpu)
{
    struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;

    memset(x86_cpu, 0, sizeof(*x86_cpu));

    x86_cpu->edx = 0x600;
    x86_cpu->eflags = 0x2;
    x86_cpu->eip = 0x0000FFF0;

    reset_x86_segment(&x86_cpu->cs, 0x3);
    x86_cpu->cs.base = 0xFFFF0000;
    x86_cpu->cs.selector = 0xF000;

    reset_x86_segment(&x86_cpu->ds, X86_SEG_TYPE_RW | X86_SEG_TYPE_ACCESSED);
    reset_x86_segment(&x86_cpu->ss, X86_SEG_TYPE_RW | X86_SEG_TYPE_ACCESSED);
    reset_x86_segment(&x86_cpu->es, X86_SEG_TYPE_RW | X86_SEG_TYPE_ACCESSED);
    reset_x86_segment(&x86_cpu->fs, X86_SEG_TYPE_RW | X86_SEG_TYPE_ACCESSED);
    reset_x86_segment(&x86_cpu->gs, X86_SEG_TYPE_RW | X86_SEG_TYPE_ACCESSED);
    reset_x86_segment(&x86_cpu->tr, X86_SEG_TYPE_RW);
    reset_x86_segment(&x86_cpu->ldt, X86_SEG_TYPE_RW);

    reset_x86_dtbl(&x86_cpu->gdt);
    reset_x86_dtbl(&x86_cpu->idt);

    x86_cpu->cr0 = 0x60000010;
    x86_cpu->apic_base = 0xFEE00000 | (1ul << 11); /* Default address + enable bit */
}

/** Set x86 general purpose registers for KVM */
static void kvm_set_regs(const struct kvm_vcpu* vcpu)
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
static void kvm_set_sregs(const struct kvm_vcpu* vcpu)
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
    struct kvm_vcpu* vcpu = (struct kvm_vcpu*) arg;
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

static int init_vcpu(struct kvm_vm* vm, struct kvm_vcpu* vcpu, uint32_t id)
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

    reset_x86_bsp(vcpu);

    kvm_set_regs(vcpu);
    kvm_set_sregs(vcpu);

    res = pthread_create(&vcpu->tid, NULL, vcpu_thread, vcpu);
    if (res != 0) {
        WBVM_LOG_ERROR2(res, "failed to create vcpu thread");
        return res;
    }

    return 0;
}

static int init_memory(struct kvm_vm* vm, uint64_t memsize)
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

static int init_vm(struct kvm_vm* vm, uint64_t memsize)
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

static struct kvm_vm g_vm;

int main(int argc, char** argv)
{
    int res = 0;

    res = kvm_init();
    if (res != 0) {
        WBVM_DIE("failed to init KVM");
    }

    res = init_vm(&g_vm, VM_MEMSIZE);
    if (res != 0) {
        WBVM_DIE("failed to init vm");
    }

    do { } while (1);
    return EXIT_SUCCESS;
}
