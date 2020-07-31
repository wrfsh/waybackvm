/*
 * Implementation of a qemu debug IO port device
 */

#include "wbvm/platform.h"
#include "wbvm/dev.h"
#include "wbvm/pio.h"

#include <stdio.h>

struct qemudbg_dev
{
    /* Base device, must be first */
    struct vdev vdev;

    /* File stream we're writing to */
    FILE* output;
};

static int qemudbg_pio_read(struct vdev* dev, uint16_t addr, unsigned size, uint32_t* out_val)
{
    /* Reading is unimplemented, decode to -1 */
    *out_val = (uint32_t) -1;
    return 0;
}

static int qemudbg_pio_write(struct vdev* vdev, uint16_t addr, unsigned size, uint32_t val)
{
    WBVM_VERIFY(size == 1);

    struct qemudbg_dev* s = container_of(vdev, struct qemudbg_dev, vdev);
    size_t nwritten = fwrite(&val, 1, 1, s->output);
    if (nwritten != 1) {
        WBVM_LOG_ERROR("Failed to write to output file");
        return -1;
    }

    fflush(s->output);
    return 0;
}

static struct pio_ops qemudbg_ops = {
    .pio_read = qemudbg_pio_read,
    .pio_write = qemudbg_pio_write,
};

static int qemudbg_init(struct vdev* vdev, int argc, const char* const* argv)
{
    struct qemudbg_dev* s = container_of(vdev, struct qemudbg_dev, vdev);

    if (argc == 0) {
        s->output = stdout;
    } else if (argc == 1) {
        const char* path = argv[0];
        s->output = fopen(path, "w");
        if (!s->output) {
            WBVM_LOG_ERROR("Could not open file %s", path);
            return -1;
        }
    }

    register_pio_region(&s->vdev, 0x402, 1, &qemudbg_ops);
    return 0;
}

WBVM_REGISTER_DEVICE_TYPE(qemudbg, sizeof(struct qemudbg_dev), qemudbg_init, NULL);
