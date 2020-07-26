#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>

#include "wbvm/platform.h"
#include "wbvm/x86.h"

/**
 * Address region in an interval inside address space.
 * Regions can be nested, but can never overlap each other on the same nesting level.
 */
struct address_range
{
    /* First addressable gpa of this range within address space */
    gpa_t first;

    /* Last addressable gpa of this range within address space */
    gpa_t last;

    /* List of next level children sorted by offset */
    LIST_HEAD(, address_range) subranges;

    /* Owning parent subrange list link */
    LIST_ENTRY(address_range) link;

    /* Referenced memory region if mapped, NULL otherwise */
    struct memory_region* mem;

    /* Host virtual address offset within mapped memory region */
    uint64_t mem_offset;
};

void address_range_init(struct address_range* r, gpa_t first, gpa_t last);

/** Address range contains a gpa? */
bool address_range_contains_addr(const struct address_range* r, gpa_t addr);

/** Address range r contains subr entirely? */
bool address_range_contains(const struct address_range* r, const struct address_range* subr);

/** Address ranges overlap? */
bool address_range_overlaps(const struct address_range* r1, const struct address_range* r2);

/**
 * Add subrange on top of existing range.
 * All GPAs withing new subrange will be resolved to it overriding parent range.
 * Subrange must be completely contains in parent range.
 */
void address_range_add_subrange(struct address_range* r, struct address_range* subr);

/**
 * Find address range that contains an address.
 * Will search among provided range and its subranges, will return the bottom-most leaf subrange.
 */
struct address_range* address_range_lookup(struct address_range* r, gpa_t addr);

/**
 * Callback type for address_space_walk.
 *
 * \r       Address range that we're walking now.
 * \first   First addressable gpa within the range for this segment.
 * \last    Last addressable gpa within the range for this segment.
 * \ctx     Caller cookie.
 */
typedef void(*address_range_segment_cb)(
    struct address_range* r,
    gpa_t first,
    gpa_t last,
    void* ctx);

/**
 * Take an address range and a callback and call it for each segment we have in that range.
 * A segment is a portion of a range that has no subranges covering it.
 * Order of returned segments is undefined, but entire region will be covered in total.
 */
void address_range_walk_segments(struct address_range* r, address_range_segment_cb segment_cb, void* ctx);

/**
 * Address space, a container for range hirarchy.
 */
struct address_space
{
    /* Dummy unmapped root range that covers an entire address space */
    struct address_range root;
};

void address_space_init(struct address_space* as, gpa_t first, gpa_t last);

/**
 * Find address range that contains an address.
 * Will the bottom-most leaf subrange.
 */
struct address_range* address_space_lookup_region(struct address_space* as, gpa_t addr);

/**
 * Map a new address range.
 *
 * Newly mapped range will be the bottom-most leaf subrange of its parent range.
 * New range may not intersect existing ranges and should be entirely within its parent range.
 *
 * Returns new range.
 */
struct address_range* address_space_map_range(struct address_space* as, gpa_t first, gpa_t last);

/**
 * Tale a callback and call it for each segment we have in this address space.
 *
 * A segment is a portion of a range that has no subranges covering it.
 * Order of returned segments is undefined, but entire region will be covered in total.
 */
void address_space_walk_segments(struct address_space* as, address_range_segment_cb segment_cb, void* ctx);
