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
    uint16_t vendor_id = 0;
    uint16_t product_id = 0;
    pid_t owner_pid = 0;
    uint8_t endpoint_in = 0x81;   // EP 1 IN (default HID)
    uint8_t endpoint_out = 0x01;  // EP 1 OUT (default HID)

    NoteBytes::Object to_notebytes() const {
        NoteBytes::Object obj;
        obj.add(NoteMessaging::Keys::DEVICE_ID, device_id);
        obj.add(NoteMessaging::Keys::INTERFACE_NUMBER, interface_number);
        obj.add(NoteMessaging::Keys::KERNEL_DRIVER_ATTACHED, kernel_driver_attached);
        obj.add(NoteMessaging::Keys::VENDOR_ID, static_cast<int32_t>(vendor_id));
        obj.add(NoteMessaging::Keys::PRODUCT_ID, static_cast<int32_t>(product_id));
        // Note: handle is a pointer, we don't serialize it
        return obj;
    }
};

#endif // USB_DEVICE_DESCRIPTOR_H