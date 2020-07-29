#pragma once

#include <stdint.h>
#include <sys/queue.h>

struct vdev
{
    /* Device type */
    struct vdev_type* type;

    /* Device list link  */
    LIST_ENTRY(vdev) link;
};

struct vdev_type
{
    /* Unique device type name */
    const char *name;

    /* Size of fully-typed device instance */
    size_t instance_size;

    /* Device construction handler */
    int (*init) (struct vdev* vdev, int argc, const char* const* argv);

    /* Device destruction handler */
    int (*uninit) (struct vdev* vdev);

    /* Private part */

    LIST_ENTRY(vdev_type) link;
};

/**
 * Create a device instance with type name and arguments.
 *
 * \type_name   Device unique type name.
 * \argc        Arguments count.
 * \argv        Arguments list.
 */
struct vdev* create_device(const char* type_name, int argc, const char* const* argv);

/**
 * Deinitialize and free emulated device
 */
void destroy_device(struct vdev* vdev);

/**
 * Register a new device type.
 *
 * \name    Unique device type name
 * \init    Device construction handler
 */
void register_device_type(struct vdev_type* type);

/**
 * A wrapper for register_device_type to call it as a ctor.
 */
#define WBVM_REGISTER_DEVICE_TYPE(_name, _instance_size, _init, _uninit) \
    static void WBVM_CTOR _name ## _register(void) \
    { \
        static struct vdev_type the_type = { \
            .name = #_name, \
            .instance_size = (_instance_size), \
            .init = (_init), \
            .uninit = (_uninit), \
        }; \
        register_device_type(&the_type); \
    }
