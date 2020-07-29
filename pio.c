#include "wbvm/platform.h"
#include "wbvm/pio.h"

/**
 * Port IO registered region.
 * Takes up a range of IO ports and binds them to a device callback.
 */
struct pio_region
{
    struct vdev* dev;
    const struct pio_ops* ops;

    uint16_t base;
    uint16_t size;
};

/**
 * Port IO address space.
 * Similar to physical address space but simpler since we don't support nesting.
 * We manage it by a simple list of registered extents.
 */
struct pio_address_space
{
    /* Array of regions sorted by pio base */
    struct pio_region* regions;

    /* Remaining space in regions array */
    size_t capacity;

    /* Current number of elements in regions array */
    size_t size;
};

static struct pio_address_space pio_address_space = {
    .regions = NULL,
    .capacity = 0,
    .size = 0,
};

static void reset_pio_space(void)
{
    wbvm_free(pio_address_space.regions);
    memset(&pio_address_space, 0, sizeof(pio_address_space));
}

int register_pio_region(struct vdev* dev, uint16_t base, uint16_t size, const struct pio_ops* ops)
{
    /* If there's no capacity left for a new region, then expand */
    if (pio_address_space.capacity == pio_address_space.size) {
        pio_address_space.capacity += 32;
        pio_address_space.regions =
            wbvm_realloc(pio_address_space.regions,
                         sizeof(*pio_address_space.regions) * pio_address_space.capacity);
    }

    /* Find place for a new region */
    size_t index = 0;
    size_t last = pio_address_space.size;
    while (index < last) {
        size_t pos = index + ((last - index) >> 1);
        struct pio_region* region = pio_address_space.regions + pos;

        if (region->base >= (base + size)) {
            last = pos;
        } else if (region->base + region->size <= base) {
            index = pos + 1;
        } else {
            /* Region intersects the new one, which is a bad argument */
            WBVM_LOG_ERROR("New PIO region base 0x%hx size %hu intersects an existing region",
                           base, size);
            return -EINVAL;
        }
    }

    /* Move all regions larger than new by 1 position to the end of the array and init new */
    struct pio_region* region = pio_address_space.regions + index;
    memmove(region + 1, region, sizeof(*region) * (pio_address_space.size - index));
    region->dev = dev;
    region->ops = ops;
    region->base = base;
    region->size = size;
    pio_address_space.size++;

    return 0;
}

static struct pio_region* lookup_region(uint16_t addr)
{
    /* Binary search a region that has our base IO port */
    size_t index = 0;
    size_t last = pio_address_space.size;
    while (index < last) {
        size_t pos = index + ((last - index) >> 1);
        struct pio_region* region = pio_address_space.regions + pos;

        if (region->base > addr) {
            last = pos;
        } else if (region->base + region->size <= addr) {
            index = pos + 1;
        } else {
            /* Hit a region */
            return region;
        }
    }

    return NULL;
}

int resolve_pio_read(uint16_t addr, unsigned opsize, uint32_t* val)
{
    struct pio_region* r = lookup_region(addr);
    if (!r) {
        return -ENODEV;
    }

    return r->ops->pio_read(r->dev, addr, opsize, val);
}

int resolve_pio_write(uint16_t addr, unsigned opsize, uint32_t val)
{
    struct pio_region* r = lookup_region(addr);
    if (!r) {
        return -ENODEV;
    }

    return r->ops->pio_write(r->dev, addr, opsize, val);
}

/*
 * Unit tests
 */

#include "wbvm/test.h"

WBVM_TEST(pio_regions_test)
{
    reset_pio_space();

    /* Build region list with some gaps */
    CU_ASSERT_EQUAL(register_pio_region(NULL, 1, 2, NULL), 0);
    CU_ASSERT_EQUAL(register_pio_region(NULL, 5, 2, NULL), 0);

    /* Insert new regions into the gaps */
    CU_ASSERT_EQUAL(register_pio_region(NULL, 0, 1, NULL), 0);
    CU_ASSERT_EQUAL(register_pio_region(NULL, 3, 2, NULL), 0);
    CU_ASSERT_EQUAL(register_pio_region(NULL, 7, 1, NULL), 0);

    /* Check what we got in address space */
    CU_ASSERT_EQUAL(pio_address_space.size, 5);
    CU_ASSERT_EQUAL(pio_address_space.regions[0].base, 0);
    CU_ASSERT_EQUAL(pio_address_space.regions[0].size, 1);
    CU_ASSERT_EQUAL(pio_address_space.regions[1].base, 1);
    CU_ASSERT_EQUAL(pio_address_space.regions[1].size, 2);
    CU_ASSERT_EQUAL(pio_address_space.regions[2].base, 3);
    CU_ASSERT_EQUAL(pio_address_space.regions[2].size, 2);
    CU_ASSERT_EQUAL(pio_address_space.regions[3].base, 5);
    CU_ASSERT_EQUAL(pio_address_space.regions[3].size, 2);
    CU_ASSERT_EQUAL(pio_address_space.regions[4].base, 7);
    CU_ASSERT_EQUAL(pio_address_space.regions[4].size, 1);

    /* Resolve some correct addresses */
    for (uint16_t i = 0; i < 7; ++i) {
        struct pio_region* r = lookup_region(i);
        CU_ASSERT_TRUE(r != NULL);
        CU_ASSERT_TRUE(r->base <= i && i <= r->base + r->size - 1);
    }

    /* Resolve some wrong addresses */
    CU_ASSERT_EQUAL(lookup_region(8), NULL);
}

WBVM_TEST(pio_regions_intersect_test)
{
    reset_pio_space();

    CU_ASSERT_EQUAL(register_pio_region(NULL, 3, 2, NULL), 0);

    /* Intersect a region at the beginning */
    CU_ASSERT_EQUAL(register_pio_region(NULL, 2, 2, NULL), -EINVAL);

    /* Intersect a region at the end */
    CU_ASSERT_EQUAL(register_pio_region(NULL, 4, 2, NULL), -EINVAL);

    /* Intersect a region at the middle */
    CU_ASSERT_EQUAL(register_pio_region(NULL, 3, 2, NULL), -EINVAL);
}
