#include "wbvm/platform.h"
#include "wbvm/x86.h"

void reset_x86_segment(struct x86_segment* seg, uint8_t type)
{
    seg->base = 0;
    seg->limit = 0xFFFF;
    seg->selector = 0;
    seg->type = type;
    seg->dpl = 0;
    seg->flags = X86_SEG_P;
}

void reset_x86_dtbl(struct x86_dtbl* dtbl)
{
    dtbl->base = 0;
    dtbl->limit = 0xFFFF;
}

void reset_x86_bsp(struct x86_cpu_state* x86_cpu)
{
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
