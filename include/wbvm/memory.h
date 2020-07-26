/**
 * Memory management
 */

#pragma once

#include "wbvm/address_space.h"

/**
 * Defines a block of host memory, or an emulated region.
 */
struct memory_region
{
    /* Mapped hva */
    void* mem;

    /* Mapped size in bytes */
    size_t size;

    /* Optional human-readable tag */
    const char* tag;
};

/**
 * Init anonymous host memory region.
 *
 * \mr      Region to init
 * \memsize Size of anonymous memory in bytes
 * \prot    Mapping protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
 * \tag     Optional human-readable tag for debugging
 */
void init_host_memory_region(struct memory_region* mr, size_t memsize, int prot, const char* tag);

/**
 * Init file-backed memory region.
 *
 * \mr      Region to init
 * \path    File path to map
 * \prot    Mapping protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
 * \tag     Optional human-readable tag for debugging
 */
void init_file_region(struct memory_region* mr, const char* path, int prot, const char* tag);

/**
 * Unmap whatever was mapped for this region.
 */
void release_memory_region(struct memory_region* mr);

/**
 * Map memory region into guest physical address space.
 *
 * Will create a new address range that covers requested gpa range and bind it with mr.
 * Newly allocated address range will be a leaf range inside its parent region, i.e.
 * all new requests into new GPA range will resolve into this mr until something overlays it.
 *
 * \as      Address space to map to
 * \mr      Memory region
 * \offset  Offset within memory region mapped host memory
 * \gpa     First addressable GPA.
 *          Last addressable GPA is calculated from region size and offset.
 */
void map_memory_region(struct address_space* as, struct memory_region* mr, size_t offset, gpa_t gpa);
