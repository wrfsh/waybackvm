#pragma once

struct vdev;

struct pio_ops
{
    int (*pio_read) (struct vdev* dev, uint16_t addr, unsigned opsize, uint32_t* out_val);
    int (*pio_write) (struct vdev* dev, uint16_t addr, unsigned opsize, uint32_t val);
};

int register_pio_region(struct vdev* dev, uint16_t base, uint16_t size, const struct pio_ops* ops);

int resolve_pio_read(uint16_t addr, unsigned opsize, uint32_t* val);
int resolve_pio_write(uint16_t addr, unsigned opsize, uint32_t val);
