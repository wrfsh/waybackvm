#include "wbvm/platform.h"
#include "wbvm/x86.h"

void reset_x86_segment(struct x86_segment* seg,
                       uint32_t base,
                       uint16_t selector,
                       uint8_t type,
                       uint8_t flags)
{
    seg->base = base;
    seg->limit = 0xFFFF;
    seg->selector = selector;
    seg->type = type;
    seg->dpl = 0;
    seg->flags = flags;
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

    reset_x86_segment(&x86_cpu->cs, 0xffff0000, 0xf000, X86_SEG_TYPE_CS | X86_SEG_TYPE_ACC, X86_SEG_P | X86_SEG_S);
    reset_x86_segment(&x86_cpu->ds, 0, 0, X86_SEG_TYPE_DS | X86_SEG_TYPE_ACC, X86_SEG_P | X86_SEG_S);
    reset_x86_segment(&x86_cpu->ss, 0, 0, X86_SEG_TYPE_DS | X86_SEG_TYPE_ACC, X86_SEG_P | X86_SEG_S);
    reset_x86_segment(&x86_cpu->es, 0, 0, X86_SEG_TYPE_DS | X86_SEG_TYPE_ACC, X86_SEG_P | X86_SEG_S);
    reset_x86_segment(&x86_cpu->fs, 0, 0, X86_SEG_TYPE_DS | X86_SEG_TYPE_ACC, X86_SEG_P | X86_SEG_S);
    reset_x86_segment(&x86_cpu->gs, 0, 0, X86_SEG_TYPE_DS | X86_SEG_TYPE_ACC, X86_SEG_P | X86_SEG_S);
    reset_x86_segment(&x86_cpu->tr, 0, 0, X86_SEG_TYPE_TSS, X86_SEG_P);
    reset_x86_segment(&x86_cpu->ldt, 0, 0, X86_SEG_TYPE_LDT, X86_SEG_P);

    reset_x86_dtbl(&x86_cpu->gdt);
    reset_x86_dtbl(&x86_cpu->idt);

    x86_cpu->cr0 = 0x60000010;
    x86_cpu->apic_base = 0xFEE00000 | (1ul << 11); /* Default address + enable bit */
}
