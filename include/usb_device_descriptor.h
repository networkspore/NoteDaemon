#ifndef USB_DEVICE_DESCRIPTOR_H
#define USB_DEVICE_DESCRIPTOR_H

#include <libusb-1.0/libusb.h>
#include <memory>
#include <string>
#include "note_messaging.h"
#include "notebytes.h"

struct USBDeviceDescriptor {
    libusb_device_handle* handle = nullptr;
    int interface_number = 0;
    bool kernel_driver_attached = false;
    std::string device_id;

    NoteBytes::Object to_notebytes() const {
        NoteBytes::Object obj;
        obj.add(NoteMessaging::Keys::DEVICE_ID, device_id);
        obj.add(NoteMessaging::Keys::INTERFACE_NUMBER, interface_number);
        obj.add(NoteMessaging::Keys::KERNEL_DRIVER_ATTACHED, kernel_driver_attached);
        // Note: handle is a pointer, we don't serialize it
        return obj;
    }
};

#endif // USB_DEVICE_DESCRIPTOR_H