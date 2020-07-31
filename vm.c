#include "wbvm/platform.h"
#include "wbvm/kvm.h"
#include "wbvm/vm.h"
#include "wbvm/pio.h"
#include "wbvm/dev.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

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
static void commit_address_space(struct vm* vm)
{
    if (!vm->physical_address_space.is_dirty) {
        return;
    }

    address_space_walk_segments(&vm->physical_address_space, register_segment, vm);
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
        {"qemudbg", 1, {"/tmp/qemudbg.log"}},
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
