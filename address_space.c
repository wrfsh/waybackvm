#include <stdlib.h>
#include <stdbool.h>

#include <wbvm/address_space.h>

void address_range_init(struct address_range* r, gpa_t first, gpa_t last, struct address_space* as)
{
    WBVM_VERIFY(r);
    WBVM_VERIFY(last >= first);

    r->first = first;
    r->last = last;
    r->mem = NULL;
    r->mem_offset = 0;
    r->as = as;
    LIST_INIT(&r->subranges);
}

bool address_range_contains_addr(const struct address_range* r, gpa_t addr)
{
    WBVM_VERIFY(r);
    return r->first <= addr && addr <= r->last;
}

bool address_range_contains(const struct address_range* r, const struct address_range* subr)
{
    WBVM_VERIFY(r && subr);
    return r->first <= subr->first && subr->last <= r->last;
}

bool address_range_overlaps(const struct address_range* r1, const struct address_range* r2)
{
    WBVM_VERIFY(r1 && r2);
    return WBVM_MAX(r1->first, r2->first) <= WBVM_MIN(r1->last, r2->last);
}

void address_range_add_subrange(struct address_range* r, struct address_range* subr)
{
    WBVM_VERIFY(r && subr);

    /* Check that subrange fits inside its parent */
    WBVM_VERIFY(address_range_contains(r, subr));

    /* Find place for new subrange checking that it does not intersect any of them as well */
    struct address_range* next = LIST_FIRST(&r->subranges);
    struct address_range* prev = NULL;
    while (next && subr->first > next->first) {
        prev = next;
        next = LIST_NEXT(next, link);
    }

    /* If previous/next regions exist, make sure any of them does not overlap new one */
    WBVM_VERIFY(!prev || !address_range_overlaps(prev, subr));
    WBVM_VERIFY(!next || !address_range_overlaps(next, subr));

    if (prev == NULL) {
        LIST_INSERT_HEAD(&r->subranges, subr, link);
    } else {
        LIST_INSERT_AFTER(prev, subr, link);
    }

    /* Mark our address space dirty since there is new subrange */
    r->as->is_dirty = true;
}

struct address_range* address_range_lookup(struct address_range* r, gpa_t addr)
{
    WBVM_VERIFY(r);

    if (!address_range_contains_addr(r, addr)) {
        return NULL;
    }

    struct address_range* subr;

    /* At least this region has the address, but go over subranges too */
check_subranges:
    LIST_FOREACH(subr, &r->subranges, link) {
        if (subr->first > addr) {
            return r;
        }

        if (address_range_contains_addr(subr, addr)) {
            r = subr;
            goto check_subranges;
        }
    }

    return r;
}

void address_range_walk_segments(struct address_range* r, address_range_segment_cb segment_cb, void* ctx)
{
    WBVM_VERIFY(r);
    WBVM_VERIFY(segment_cb);

    gpa_t first = r->first;
    struct address_range* subr;
    LIST_FOREACH(subr, &r->subranges, link) {
        if (subr->first > first) {
            /* Walk a gap between children's segments */
            segment_cb(r, first, subr->first - 1, ctx);
        }

        /* Walk child segment */
        address_range_walk_segments(subr, segment_cb, ctx);

        /* Ok to overflow GPA here.
         * If subrange ends at the max possible GPA, then this is the last possible subrange. */
        first = subr->last + 1;
    }

    /* Handle tail gap.
     * Be carefull to handle possibly overflowed first gpa (by overflowing last as well). */
    if (r->last + 1 != first) {
        segment_cb(r, first, r->last, ctx);
    }
}

void address_space_init(struct address_space* as, gpa_t first, gpa_t last)
{
    WBVM_VERIFY(as);

    address_range_init(&as->root, first, last, as);
    as->is_dirty = false;
}

struct address_range* address_space_lookup_region(struct address_space* as, gpa_t addr)
{
    WBVM_VERIFY(as);
    return address_range_lookup(&as->root, addr);
}

struct address_range* address_space_map_range(struct address_space* as, gpa_t first, gpa_t last)
{
    WBVM_VERIFY(as);

    /* Find the region that currently maps requested range and map on top of it */
    struct address_range* base_ar = address_space_lookup_region(as, first);
    WBVM_VERIFY(base_ar);

    struct address_range* ar = wbvm_alloc(sizeof(*ar));
    address_range_init(ar, first, last, as);
    address_range_add_subrange(base_ar, ar);

    return ar;
}

void address_space_walk_segments(struct address_space* as, address_range_segment_cb segment_cb, void* ctx)
{
    WBVM_VERIFY(as);
    address_range_walk_segments(&as->root, segment_cb, ctx);
}

/*
 * Unit tests
 */

#include <wbvm/test.h>

static struct address_range make_address_range(gpa_t first, gpa_t last)
{
    struct address_range r;
    address_range_init(&r, first, last, NULL);
    return r;
}

WBVM_TEST(address_range_overlaps_test)
{
    struct address_range r1, r2;

    /* Regions connect but don't overlap */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(4, 6);
    CU_ASSERT_FALSE(address_range_overlaps(&r1, &r2));
    CU_ASSERT_FALSE(address_range_overlaps(&r2, &r1));

    /* Regions don't connect and don't overlap */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(5, 7);
    CU_ASSERT_FALSE(address_range_overlaps(&r1, &r2));
    CU_ASSERT_FALSE(address_range_overlaps(&r2, &r1));

    /* Regions overlap by 1 unit */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(3, 5);
    CU_ASSERT_TRUE(address_range_overlaps(&r1, &r2));
    CU_ASSERT_TRUE(address_range_overlaps(&r2, &r1));

    /* Regions are identical */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(1, 3);
    CU_ASSERT_TRUE(address_range_overlaps(&r1, &r2));
    CU_ASSERT_TRUE(address_range_overlaps(&r2, &r1));
}

WBVM_TEST(address_range_contains_addr_test)
{
    struct address_range r1 = make_address_range(1, 2);

    CU_ASSERT_FALSE(address_range_contains_addr(&r1, 0));
    CU_ASSERT_TRUE(address_range_contains_addr(&r1, 1));
    CU_ASSERT_TRUE(address_range_contains_addr(&r1, 2));
    CU_ASSERT_FALSE(address_range_contains_addr(&r1, 3));
}

WBVM_TEST(address_range_contains_test)
{
    struct address_range r1, r2;

    /* Regions connect but don't overlap */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(4, 6);
    CU_ASSERT_FALSE(address_range_contains(&r1, &r2));
    CU_ASSERT_FALSE(address_range_contains(&r2, &r1));

    /* Regions overlap but don't contain each other */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(3, 5);
    CU_ASSERT_FALSE(address_range_contains(&r1, &r2));
    CU_ASSERT_FALSE(address_range_contains(&r2, &r1));

    /* One region contains the other and vise versa */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(1, 3);
    CU_ASSERT_TRUE(address_range_contains(&r1, &r2));
    CU_ASSERT_TRUE(address_range_contains(&r2, &r1));

    /* One region contains the other but not the other way around */
    r1 = make_address_range(1, 3);
    r2 = make_address_range(2, 2);
    CU_ASSERT_TRUE(address_range_contains(&r1, &r2));
    CU_ASSERT_FALSE(address_range_contains(&r2, &r1));
}

static void mark_ranges_seen(struct address_range* r, gpa_t first, gpa_t last, void* ctx)
{
    struct address_range** seen = (struct address_range**) ctx;

    while (first <= last) {
        CU_ASSERT_EQUAL(seen[first], NULL);
        seen[first] = r;
        ++first;
    }
}

WBVM_TEST(nested_regions_test)
{
    /**
     * Build the following address space region structure and query it:
     *
     * 1 2 3 4 5 6 7 8 9
     * +-+-+-+-+-+-+-+-+
     *   =======   ===
     *   = =   =
     */

    struct address_space as;
    address_space_init(&as, 1, 9);

    struct address_range* subranges[5] = {NULL};
    subranges[0] = address_space_map_range(&as, 2, 5);
    subranges[1] = address_space_map_range(&as, 7, 8);
    subranges[2] = address_space_map_range(&as, 2, 2);
    subranges[3] = address_space_map_range(&as, 3, 3);
    subranges[4] = address_space_map_range(&as, 5, 5);

    /*
     * Valid lookups
     */

    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 1), &as.root);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 2), subranges[2]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 3), subranges[3]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 4), subranges[0]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 5), subranges[4]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 6), &as.root);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 7), subranges[1]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 8), subranges[1]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 9), &as.root);

    /*
     * OOB lookups
     */

    CU_ASSERT_EQUAL(address_space_lookup_region(&as, as.root.first - 1), NULL);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, as.root.last + 1), NULL);

    /*
     * Walk the segments and mark ranges we've seen for all our addresses
     */

    struct address_range* ranges_seen[10] = {NULL};
    address_space_walk_segments(&as, mark_ranges_seen, ranges_seen);
    CU_ASSERT_EQUAL(ranges_seen[0], NULL);
    CU_ASSERT_EQUAL(ranges_seen[1], &as.root);
    CU_ASSERT_EQUAL(ranges_seen[2], subranges[2]);
    CU_ASSERT_EQUAL(ranges_seen[3], subranges[3]);
    CU_ASSERT_EQUAL(ranges_seen[4], subranges[0]);
    CU_ASSERT_EQUAL(ranges_seen[5], subranges[4]);
    CU_ASSERT_EQUAL(ranges_seen[6], &as.root);
    CU_ASSERT_EQUAL(ranges_seen[7], subranges[1]);
    CU_ASSERT_EQUAL(ranges_seen[8], subranges[1]);
    CU_ASSERT_EQUAL(ranges_seen[9], &as.root);
}

static void gpa_overflow_walk(struct address_range* r, gpa_t first, gpa_t last, void* ctx)
{
    CU_ASSERT_TRUE(
        (first == 0 && last == 0x00FFFFFF) || 
        (first == 0x01000000 && last == 0x01FFFFFF) ||
        (first == 0x02000000 && last == 0xFFFFFFFF));

    (*(size_t*)ctx)++;
}

WBVM_TEST(gpa_overflow_test)
{
    /**
     * Build roughly the following address space region structure and query it.
     * Region is constructed to cover min/max GPAs and test for various overflow cases.
     *
     * 0               FFFFFFFF
     * +-+-+-+-+-+-+-+-+
     * =======       ===
     */

    struct address_space as;
    address_space_init(&as, 0, 0xFFFFFFFF);

    struct address_range* subranges[4];
    subranges[0] = address_space_map_range(&as, 0, 0x00FFFFFF);
    subranges[1] = address_space_map_range(&as, 0x02000000, 0xFFFFFFFF);

    /*
     * Lookup borders
     */

    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 0), subranges[0]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 0x00FFFFFF), subranges[0]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 0x02000000), subranges[1]);
    CU_ASSERT_EQUAL(address_space_lookup_region(&as, 0xFFFFFFFF), subranges[1]);

    /*
     * Walk segments
     */

    size_t segments_seen = 0;
    address_space_walk_segments(&as, gpa_overflow_walk, &segments_seen);
    CU_ASSERT_EQUAL(segments_seen, 3);
}

WBVM_TEST(address_space_dirty_test)
{
    struct address_space as;
    address_space_init(&as, 0, 0xFFFFFFFF);
    CU_ASSERT_FALSE(as.is_dirty);

    address_space_map_range(&as, 0, 0x00FFFFFF);
    CU_ASSERT_TRUE(as.is_dirty);
}
