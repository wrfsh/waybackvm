#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "wbvm/platform.h"
#include "wbvm/memory.h"
#include "wbvm/kvm.h"
#include "wbvm/vm.h"

void init_host_memory_region(struct memory_region* mr, size_t memsize, int prot, const char* tag)
{
    mr->tag = tag;
    mr->size = memsize;
    mr->mem = mmap(NULL, memsize, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    WBVM_VERIFY(mr->mem != MAP_FAILED);
}

void init_file_region(struct memory_region* mr, const char* path, int prot, const char* tag)
{
    int error = 0;

    struct stat st;
    error = stat(path, &st);
    WBVM_VERIFY(!error);

    size_t image_size = st.st_size;

    int fd = open(path, O_RDONLY);
    WBVM_VERIFY(fd >= 0);

    mr->tag = tag;
    mr->mem = mmap(NULL, image_size, prot, MAP_PRIVATE, fd, 0);
    mr->size = image_size;
    close(fd);

    WBVM_VERIFY(mr->mem != MAP_FAILED);
}

void free_memory_region(struct memory_region* mr)
{
    WBVM_VERIFY(mr);
    munmap(mr->mem, mr->size);
}

void map_memory_region(struct address_space* as, struct memory_region* mr, size_t offset, gpa_t gpa)
{
    WBVM_VERIFY(mr && mr->size > 0);
    WBVM_VERIFY(offset < mr->size);

    gpa_t last = gpa + (mr->size - offset - 1);
    struct address_range* ar = address_space_map_range(as, gpa, last);
    ar->mem = mr;
    ar->mem_offset = offset;
}
