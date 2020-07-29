#include "wbvm/platform.h"
#include "wbvm/dev.h"

static LIST_HEAD(, vdev_type) registered_types = LIST_HEAD_INITIALIZER(registered_types);

void register_device_type(struct vdev_type* type)
{
    LIST_INSERT_HEAD(&registered_types, type, link);
}

struct vdev* create_device(const char* type_name, int argc, const char* const* argv)
{
    struct vdev_type* type;

    LIST_FOREACH(type, &registered_types, link) {
        if (0 == strcmp(type_name, type->name)) {

            if (type->instance_size < sizeof(struct vdev)) {
                WBVM_LOG_ERROR("Device type %s instance size %zu cannot be smaller than %zu",
                               type_name, type->instance_size, sizeof(struct vdev));
                return NULL;
            }

            struct vdev* vdev = wbvm_zalloc(type->instance_size);
            vdev->type = type;

            if (type->init) {
                int res = type->init(vdev, argc, argv);
                if (res < 0) {
                    WBVM_LOG_ERROR("Failed to initialize device type %s", type_name);
                    wbvm_free(vdev);
                    return NULL;
                }
            }

            return vdev;
        }
    }

    WBVM_LOG_ERROR("No device with type \"%s\"", type_name);
    return NULL;
}

void destroy_device(struct vdev* vdev)
{
    if (vdev && vdev->type->uninit) {
        vdev->type->uninit(vdev);
        wbvm_free(vdev);
    }
}
