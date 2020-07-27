/**
 * x86 target defnitions
 */

#pragma once

#include <stdint.h>

typedef uint32_t gpa_t;     /* Guest physical address */
typedef uint32_t gva_t;     /* Guest virtual address */
typedef uint32_t gsize_t;   /* Guest size_t */

/**
 * x86 segment descriptor
 */
struct x86_segment
{
    uint32_t base;
    uint16_t limit;
    uint16_t selector;
    uint8_t dpl;

    enum {
        X86_SEG_TYPE_DS  = 0b0010,   /* Read/Write */
        X86_SEG_TYPE_CS  = 0b1010,   /* Execute/Read */
        X86_SEG_TYPE_TSS = 0b0011,   /* 16-bit TSS */
        X86_SEG_TYPE_LDT = 0b0010,   /* LDT */
        X86_SEG_TYPE_ACC = (1 << 0), /* Accessed flag */
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

/**
 * x86 descriptor table
 */
struct x86_dtbl
{
    uint32_t base;
    uint16_t limit;
};

/**
 * Virtualized x86 cpu state
 */
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

/**
 * Reset x86 segment to default state
 */
void reset_x86_segment(struct x86_segment* seg,
                       uint32_t base,
                       uint16_t selector,
                       uint8_t type,
                       uint8_t flags);

/**
 * Reset x86 descriptor table register to default state
 */
void reset_x86_dtbl(struct x86_dtbl* dtbl);

/**
 * Reset x86 boot processor to default state after INIT
 */
void reset_x86_bsp(struct x86_cpu_state* x86_cpu);
