#include "wbvm/platform.h"
#include "wbvm/kvm.h"
#include "wbvm/vm.h"
#include "wbvm/pio.h"
#include "wbvm/dev.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

#include <capstone/capstone.h>

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

/** Get x86 general purpose registers from KVM */
static void kvm_get_regs(struct vcpu* vcpu)
{
    struct kvm_regs kvmregs;
    kvm_vcpu_ioctl_nofail(vcpu->vcpufd, KVM_GET_REGS, (uintptr_t)&kvmregs);

    struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;
    x86_cpu->eax = kvmregs.rax;
    x86_cpu->ebx = kvmregs.rbx;
    x86_cpu->ecx = kvmregs.rcx;
    x86_cpu->edx = kvmregs.rdx;
    x86_cpu->esi = kvmregs.rsi;
    x86_cpu->edi = kvmregs.rdi;
    x86_cpu->esp = kvmregs.rsp;
    x86_cpu->ebp = kvmregs.rbp;
    x86_cpu->eip = kvmregs.rip;
    x86_cpu->eflags = kvmregs.rflags;
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

/** Get x86 segment descriptor values from KVM */
static void kvm_get_seg(const struct kvm_segment* kvmseg, struct x86_segment* seg)
{
    seg->base = kvmseg->base;
    seg->limit = kvmseg->limit;
    seg->selector = kvmseg->selector;
    seg->type = kvmseg->type;
    seg->dpl = kvmseg->dpl;
    seg->flags |= (kvmseg->present ? X86_SEG_P : 0);
    seg->flags |= (kvmseg->db ? X86_SEG_DB : 0);
    seg->flags |= (kvmseg->s ? X86_SEG_S : 0);
    seg->flags |= (kvmseg->l ? X86_SEG_L : 0);
    seg->flags |= (kvmseg->g ? X86_SEG_G : 0);
    seg->flags |= (kvmseg->avl ? X86_SEG_AVL : 0);
}

static void kvm_set_dtable(struct kvm_dtable* kvm_dtable, const struct x86_dtbl* dtable)
{
    kvm_dtable->base = dtable->base;
    kvm_dtable->limit = dtable->limit;
    memset(kvm_dtable->padding, 0, sizeof(kvm_dtable->padding));
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

    kvm_set_dtable(&kvm_sregs.gdt, &x86_cpu->gdt);
    kvm_set_dtable(&kvm_sregs.idt, &x86_cpu->idt);

    kvm_sregs.cr0 = x86_cpu->cr0;
    kvm_sregs.cr2 = x86_cpu->cr2;
    kvm_sregs.cr3 = x86_cpu->cr3;
    kvm_sregs.cr4 = x86_cpu->cr4;

    kvm_sregs.efer = x86_cpu->efer;
    kvm_sregs.apic_base = x86_cpu->apic_base;

    kvm_vcpu_ioctl_nofail(vcpu->vcpufd, KVM_SET_SREGS, (uintptr_t)&kvm_sregs);
}

/** Get x86 system registers from KVM */
static void kvm_get_sregs(struct vcpu* vcpu)
{
    struct kvm_sregs kvm_sregs = {0};
    kvm_vcpu_ioctl_nofail(vcpu->vcpufd, KVM_GET_SREGS, (uintptr_t)&kvm_sregs);

    struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;
    x86_cpu->cr0 = kvm_sregs.cr0;
    x86_cpu->cr2 = kvm_sregs.cr2;
    x86_cpu->cr3 = kvm_sregs.cr3;
    x86_cpu->cr4 = kvm_sregs.cr4;

    x86_cpu->efer = kvm_sregs.efer;

    kvm_get_seg(&kvm_sregs.cs, &x86_cpu->cs);
    kvm_get_seg(&kvm_sregs.ds, &x86_cpu->ds);
    kvm_get_seg(&kvm_sregs.es, &x86_cpu->es);
    kvm_get_seg(&kvm_sregs.fs, &x86_cpu->fs);
    kvm_get_seg(&kvm_sregs.gs, &x86_cpu->gs);
    kvm_get_seg(&kvm_sregs.ss, &x86_cpu->ss);
    kvm_get_seg(&kvm_sregs.tr, &x86_cpu->tr);
    kvm_get_seg(&kvm_sregs.ldt, &x86_cpu->ldt);
}

static void dump_guest_code(struct vcpu* vcpu)
{
    kvm_get_regs(vcpu);
    kvm_get_sregs(vcpu);

    const struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;

    gpa_t ip = ((gpa_t)x86_cpu->cs.base) + x86_cpu->eip;

    uint8_t opcodes[16];
    size_t nbytes = fetch_memory(&vcpu->vm->physical_address_space, ip, opcodes, sizeof(opcodes));

    csh cs_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &cs_handle) != CS_ERR_OK) {
        return;
    }

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insns = NULL;
    size_t insn_count = cs_disasm(cs_handle, opcodes, nbytes, ip, 0, &insns);
    if (insn_count <= 0) {
        return;
    }

    cs_close(&cs_handle);

    WBVM_LOG_DEBUG("Guest code at 0x%x:", ip);
    for (size_t i = 0; i < insn_count; ++i) {
        WBVM_LOG_DEBUG("0x%08lx:\t%.*s %.*s",
                       insns[i].address,
                       (unsigned)sizeof(insns[i].mnemonic), insns[i].mnemonic,
                       (unsigned)sizeof(insns[i].op_str), insns[i].op_str);
    }

    cs_free(insns, insn_count);
}

static void dump_vcpu_state(struct vcpu* vcpu)
{
    kvm_get_regs(vcpu);
    kvm_get_sregs(vcpu);

    const struct x86_cpu_state* x86_cpu = &vcpu->x86_cpu;

    WBVM_LOG_DEBUG("VCPU %d guest state:", vcpu->id);
    WBVM_LOG_DEBUG("EAX = %08x, EBX = %08x, ECX = %08x, EDX = %08x",
                   x86_cpu->eax, x86_cpu->ebx, x86_cpu->ecx, x86_cpu->edx);
    WBVM_LOG_DEBUG("ESI = %08x, EDI = %08x, EBP = %08x, ESP = %08x",
                   x86_cpu->esi, x86_cpu->edi, x86_cpu->ebp, x86_cpu->esp);
    WBVM_LOG_DEBUG("EIP = %08x",
                   x86_cpu->eip);
    WBVM_LOG_DEBUG("EFLAGS = %08x",
                   x86_cpu->eflags);
    WBVM_LOG_DEBUG("CR0 = %08x, CR2 = %08x, CR3 = %08x, CR4 = %08x, EFER = %08x",
                   x86_cpu->cr0, x86_cpu->cr2, x86_cpu->cr3, x86_cpu->cr4, x86_cpu->efer);
    WBVM_LOG_DEBUG("CS = %04hx, DS = %04hx, ES = %04hx, SS = %04hx, FS = %04hx, GS = %04hx",
                   x86_cpu->cs.selector, x86_cpu->ds.selector, x86_cpu->es.selector,
                   x86_cpu->ss.selector, x86_cpu->fs.selector, x86_cpu->gs.selector);

    dump_guest_code(vcpu);
}

static void kvm_reg_memory_region(struct vm* vm, int slot, gpa_t first, gpa_t last, bool readonly, uintptr_t hva)
{
    struct kvm_userspace_memory_region memregion;
    memregion.slot = slot;
    memregion.flags = readonly ? KVM_MEM_READONLY : 0;
    memregion.guest_phys_addr = first;
    memregion.memory_size = (uint64_t)last - first + 1;
    memregion.userspace_addr = hva;

    kvm_vm_ioctl_nofail(vm->vmfd, KVM_SET_USER_MEMORY_REGION, (uintptr_t) &memregion);
}

static void register_segment(struct address_range* r, gpa_t first, gpa_t last, void* ctx)
{
    if (!r->mem) {
        /* Skip unmapped segment */
        return;
    }

    struct vm* vm = (struct vm*) ctx;
    struct memory_region* mr = r->mem;
    uintptr_t hva = (uintptr_t) mr->mem + r->mem_offset;
    WBVM_LOG_DEBUG("Adding KVM memory slot: [%#x - %#x], mem region \"%s\", hva %#lx",
                   first, last, (mr->tag ? mr->tag : ""), hva);

    kvm_reg_memory_region(vm, vm->next_slot++, first, last, false, hva);
}

/**
 * Commit any changes done to VM physical address space to hypervisor.
 */
void commit_address_space(struct vm* vm)
{
    if (!vm->physical_address_space.is_dirty) {
        return;
    }

    address_space_walk_segments(&vm->physical_address_space, register_segment, vm);
}

static int handle_io_exit(struct vcpu* vcpu)
{
    volatile struct kvm_run* kvm_run = vcpu->kvm_run;

    WBVM_LOG_DEBUG("KVM_EXIT_IO: dir = %d, size = %d, port = 0x%hx, count = %d, offset = %llx",
            kvm_run->io.direction,
            kvm_run->io.size,
            kvm_run->io.port,
            kvm_run->io.count,
            kvm_run->io.data_offset);

    void* pdata = (void*)kvm_run + kvm_run->io.data_offset;

    for (uint32_t i = 0; i < kvm_run->io.count; ++i) {
        int res = 0;

        if (kvm_run->io.direction == KVM_EXIT_IO_IN) {
            res = resolve_pio_read(kvm_run->io.port, kvm_run->io.size, (uint32_t*) pdata);
        } else {
            res = resolve_pio_write(kvm_run->io.port, kvm_run->io.size, *(uint32_t*) pdata);
        }

        if (res < 0) {
            WBVM_LOG_ERROR("Could not resolve PIO address 0x%hx", kvm_run->io.port);
            return res;
        }
    }

    return 0;
}

static int vcpu_handle_exit(struct vcpu* vcpu)
{
    volatile struct kvm_run* kvm_run = vcpu->kvm_run;

    switch (kvm_run->exit_reason) {
    case KVM_EXIT_IO:
        return handle_io_exit(vcpu);

    case KVM_EXIT_FAIL_ENTRY:
        WBVM_LOG_ERROR("VCPU %d failed entry, hw error: %#llx",
                       vcpu->id, kvm_run->fail_entry.hardware_entry_failure_reason);
        return -1;

    default:
        WBVM_LOG_ERROR("Unknown exit reason %d", kvm_run->exit_reason);
        return -1;
    };

    return 0;
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
            break;
        }

        WBVM_LOG_DEBUG("vcpu %d exited, reason 0x%x", vcpu->id, vcpu->kvm_run->exit_reason);

        res = vcpu_handle_exit(vcpu);
        if (res != 0) {
            should_exit = true;
            dump_vcpu_state(vcpu);
        }
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

static int init_system_memory(struct vm* vm, gsize_t memsize)
{
    /* Supported memory size >= 1MB && <= 3GB */
    if (memsize < (1ull << 20) || memsize > (3ull << 30)) {
        return -1;
    }

    init_host_memory_region(&vm->ram, memsize, PROT_READ|PROT_WRITE|PROT_EXEC, "system ram");
    map_memory_region(&vm->physical_address_space, &vm->ram, 0, 0);

    return 0;
}

/** Read and map bios firmware image on expected addresses */
static int load_firmware_image(struct vm* vm, const char* path)
{
    int error = 0;

    struct stat st;
    error = stat(path, &st);
    if (error) {
        return error;
    }

    size_t image_size = st.st_size;
    if (!image_size || image_size > 256 * 1024 || image_size & 0xFFFF) {
        return -1;
    }

    WBVM_LOG_DEBUG("loading firmware image %s, size %zu", path, image_size);

    /*
     * PCAT firmware is mapped twice:
     * - Full image at end of 32-bit physical address space.
     * - At most 2 high 64KB segments are remapped at low 1MB memory, at E and F segments.
     *
     * Both regions are mapped read only.
     * The low-memory one can (and will) be unmapped by firmware later through fx440 registers.
     */

    init_file_region(&vm->firmware, path, PROT_READ, "bios.bin");
    map_memory_region(&vm->physical_address_space, &vm->firmware, 0, 0xFFFFFFFF - image_size + 1);

    size_t low_size = WBVM_MIN(128ul << 10, image_size);
    size_t low_offset = (image_size > low_size ? image_size - low_size : 0);
    map_memory_region(&vm->physical_address_space, &vm->firmware, low_offset, 0xFFFFF - low_size + 1);

    return 0;
}

static int init_devices(struct vm* vm)
{
    static const struct {
        const char* name;
        int argc;
        const char* argv[16];
    } device_list[] = {
    };

    LIST_INIT(&vm->devices);

    for (size_t i = 0; i < sizeof(device_list) / sizeof(*device_list); ++i) {
        struct vdev* vdev = create_device(device_list[i].name, device_list[i].argc, device_list[i].argv);
        if (!vdev) {
            WBVM_LOG_ERROR("Failed to init device %s", device_list[i].name);
            return -1;
        }

        LIST_INSERT_HEAD(&vm->devices, vdev, link);
    }

    return 0;
}

int init_vm(struct vm* vm, gsize_t memsize, const char* fwpath)
{
    int res = 0;

    memset(vm, 0, sizeof(*vm));

    vm->vmfd = kvm_ioctl(KVM_CREATE_VM, 0);
    if (vm->vmfd < 0) {
        WBVM_LOG_ERROR2(res, "could not create VM");
        return res;
    }

    address_space_init(&vm->physical_address_space, 0, UINT32_MAX);

    res = init_system_memory(vm, memsize);
    if (res != 0) {
        WBVM_LOG_ERROR2(res, "failed to init system memory");
        return res;
    }

    res = load_firmware_image(vm, fwpath);
    if (res != 0) {
        WBVM_LOG_ERROR2(res, "failed to load firmware image");
        return res;
    }

    commit_address_space(vm);

    res = init_devices(vm);
    if (res != 0) {
        WBVM_LOG_ERROR2(res, "failed to init devices");
        return res;
    }

    res = init_vcpu(vm, &vm->vcpu, 0);
    if (res != 0) {
        return res;
    }

    return 0;
}
