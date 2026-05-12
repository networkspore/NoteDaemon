# Device Acquisition API

## Overview

This document describes the protocol and API for discovering, claiming, and releasing devices in the NoteDaemon system. The API is designed to be通用的 across different device types (HID devices, serial devices, etc.) with module-specific implementations.

---

## Message Flow Overview

```
┌─────────┐                              ┌─────────────┐                              ┌─────────┐
│  Client │                              │ NoteDaemon  │                              │ Module  │
└────┬────┘                              └──────┬──────┘                              └────┬────┘
     │                                           │                                           │
     │──── request_discovery (CMD) ────────────>│                                           │
     │                                           │─────── (module discovery) ────────────────>│
     │                                           │<────── (device list) ─────────────────────│
     │<─── item_list (CMD) ─────────────────────│                                           │
     │                                           │                                           │
     │──── claim_item (CMD) ───────────────────>│                                           │
     │     {module_id, device_id}               │                                           │
     │                                           │─────── (claim device) ──────────────────>│
     │                                           │<────── (success/error) ─────────────────│
     │<─── item_claimed (EVENT) ───────────────│                                           │
     │     {device_id, status}                  │                                           │
     │                                           │                                           │
     │══════════ (streaming events) ════════════│═══════════════════════════════════════════│
     │                                           │                                           │
     │──── resume (CMD) ───────────────────────>│                                           │
     │     {device_id, processed_count}         │                                           │
     │                                           │─────── (update state) ──────────────────>│
     │                                           │                                           │
     │==== (more events) ═══════════════════════│═══════════════════════════════════════════│
     │                                           │                                           │
     │                                           │                                           │
     │──── release_item (CMD) ─────────────────>│                                           │
     │     {module_id, device_id}               │                                           │
     │                                           │─────── (release device) ────────────────>│
     │                                           │<────── (success/error) ─────────────────│
     │<─── item_released (EVENT) ──────────────│                                           │
     │     {device_id, status}                  │                                           │
     │                                           │                                           │
```

---

## Message Types

### 1. Discovery

#### Request Discovery

**Command:** `request_discovery`

**Direction:** Client → NoteDaemon

```json
{
  "event": "cmd",
  "cmd": "request_discovery"
}
```

#### Response: Item List

**Event:** `item_list`

**Direction:** NoteDaemon → Client

```json
{
  "event": "cmd",
  "cmd": "item_list",
  "items": [
    {
      "device_id": "1:2",
      "vendor_id": 0x1234,
      "product_id": 0x5678,
      "manufacturer": "Example Corp",
      "product": "USB Keyboard",
      "serial_number": "ABC123",
      "bus_number": 1,
      "item_address": 2,
      "item_type": "HID"
    },
    ...
  ]
}
```

**Item Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `device_id` | string | Unique device identifier (bus:address format) |
| `vendor_id` | integer | USB Vendor ID |
| `product_id` | integer | USB Product ID |
| `manufacturer` | string | Device manufacturer name |
| `product` | string | Device product name |
| `serial_number` | string | Device serial number |
| `bus_number` | integer | USB bus number |
| `item_address` | integer | USB device address |
| `item_type` | string | Device type (e.g., "HID", "Serial") |

---

### 2. Claim Device

#### Request Claim

**Command:** `claim_item`

**Direction:** Client → NoteDaemon

```json
{
  "event": "cmd",
  "cmd": "claim_item",
  "module_id": "note_usb",
  "device_id": "1:2"
}
```

**Required Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `module_id` | string | The module that handles this device |
| `device_id` | string | The device to claim |

#### Response: Item Claimed (Success)

**Event:** `item_claimed`

**Direction:** NoteDaemon → Client

```json
{
  "event": "item_claimed",
  "device_id": "1:2",
  "status": "claimed"
}
```

#### Response: Item Claimed (Error)

**Event:** `item_claimed` (with error)

**Direction:** NoteDaemon → Client

```json
{
  "event": "item_claimed",
  "device_id": "1:2",
  "error_code": 10,
  "msg": "Device not found: 1:2"
}
```

**Error Codes:**
| Code | Name | Description |
|------|------|-------------|
| 10 | DEVICE_NOT_FOUND | Device doesn't exist |
| 11 | ITEM_NOT_AVAILABLE | Device already claimed |
| 20 | PERMISSION_DENIED | Cannot open device (permission issue) |
| 24 | NOT_OWNER | Device claimed by different client |

**Error Codes:**
| Code | Name | Description |
|------|------|-------------|
| 101 | ITEM_NOT_FOUND | Device doesn't exist |
| 102 | ITEM_NOT_AVAILABLE | Device already claimed by another client |
| 103 | PERMISSION_DENIED | Cannot open device (permission issue) |
| 104 | INTERFACE_IN_USE | Interface already claimed |

---

### 3. Device Streaming

Once a device is claimed, the daemon streams events to the client.

#### Event Streaming

**Event:** (device-specific)

**Direction:** NoteDaemon → Client

The event format depends on the device type. For HID devices:
```json
{
  "event": "key_down",
  "device_id": "1:2",
  "key_code": 0x04,
  "timestamp": 1234567890
}
```

#### Client Acknowledgment

**Command:** `resume`

**Direction:** Client → NoteDaemon

```json
{
  "event": "cmd",
  "cmd": "resume",
  "device_id": "1:2",
  "processed_count": 10
}
```

The `processed_count` field tells the streaming thread how many events the client has processed, allowing backpressure management.

---

### 4. Release Device

#### Request Release

**Command:** `release_item`

**Direction:** Client → NoteDaemon

```json
{
  "event": "cmd",
  "cmd": "release_item",
  "device_id": "1:2",
  "correlation_id": "unique-correlation-id-456"
}
```

**Required Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `device_id` | string | The device to release |
| `correlation_id` | string | Unique ID for correlating request/response |

#### Response: Item Released (Success)

**Event:** `item_released`

**Direction:** NoteDaemon → Client

```json
{
  "event": "item_released",
  "device_id": "1:2",
  "correlation_id": "unique-correlation-id-456",
  "status": "success"
}
```

#### Response: Item Released (Error)

**Event:** `item_released` (with error)

**Direction:** NoteDaemon → Client

```json
{
  "event": "item_released",
  "device_id": "1:2",
  "correlation_id": "unique-correlation-id-456",
  "error_code": 101,
  "msg": "Device not claimed: 1:2"
}
```

**Error Codes:**
| Code | Name | Description |
|------|------|-------------|
| 101 | ITEM_NOT_FOUND | Device doesn't exist |
| 102 | NOT_OWNER | Device is claimed by a different client |
| 103 | ALREADY_RELEASED | Device was already released |

---

## Hotplug Events

NoteDaemon can notify clients when devices are attached or detached.

### Device Attached

**Event:** `device_attached`

**Direction:** NoteDaemon → Client (broadcast to all)

```json
{
  "event": "device_attached",
  "device_id": "1:3",
  "item_info": {
    "device_id": "1:3",
    "vendor_id": 0x1234,
    "product_id": 0x5678,
    "manufacturer": "Example Corp",
    "product": "USB Keyboard",
    "serial_number": "ABC123",
    "bus_number": 1,
    "item_address": 3,
    "item_type": "HID"
  }
}
```

### Device Detached

**Event:** `device_detached`

**Direction:** NoteDaemon → Client (broadcast to all)

```json
{
  "event": "device_detached",
  "device_id": "1:2"
}
```

### Device Disconnected

**Event:** `device_disconnected`

**Direction:** NoteDaemon → Client (for claimed devices)

```json
{
  "event": "device_disconnected",
  "device_id": "1:2",
  "msg": "USB device physically disconnected"
}
```

Note: When a device is disconnected, the client can either:
1. Wait for the device to be reattached
2. Release the device with `release_item`

---

## Module Discovery

Clients can query what modules are available and their capabilities.

#### Request Get Modules

**Command:** `get_modules`

**Direction:** Client → NoteDaemon

```json
{
  "event": "cmd",
  "cmd": "get_modules"
}
```

#### Response: Module List

**Event:** `module_list`

**Direction:** NoteDaemon → Client

```json
{
  "event": "module_list",
  "modules": [
    {
      "name": "note_usb",
      "version": "1.0.0",
      "description": "USB HID device support",
      "capabilities": 0x0001,
      "handlers": ["claim_item", "release_item", "key_down", "key_up"]
    }
  ]
}
```

**Module Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Module identifier |
| `version` | string | Module version |
| `description` | string | Human-readable description |
| `capabilities` | integer | Bitmask of capabilities |
| `handlers` | array | List of message types handled |

---

## Connection Lifecycle

### Typical Client Session

1. **Connect** → Client connects to NoteDaemon socket
2. **Hello** → Client sends `hello`, daemon responds with `ready`
3. **Discover** → Client sends `request_discovery`, gets `item_list`
4. **Claim** → Client sends `claim_item`, gets `item_claimed`
5. **Use** → Device events stream to client, client sends `resume` acknowledgments
6. **Release** → Client sends `release_item`, gets `item_released`
7. **Disconnect** → Client disconnects, daemon cleans up

### Error Handling

All commands support error responses with the following structure:

```json
{
  "event": "<original_event>",
  "error_code": <integer>,
  "msg": "<error_message>",
  "correlation_id": "<if_provided>"
}
```

---

## Protocol Constants

### Pre-defined Values (C++)

The protocol uses pre-serialized NoteBytes::Value objects for efficiency:

```cpp
// Commands
NoteMessaging::ProtocolMessages::REQUEST_DISCOVERY
NoteMessaging::ProtocolMessages::CLAIM_ITEM
NoteMessaging::ProtocolMessages::RELEASE_ITEM
NoteMessaging::ProtocolMessages::RESUME

// Events
NoteMessaging::ProtocolMessages::ITEM_LIST
NoteMessaging::ProtocolMessages::ITEM_CLAIMED
NoteMessaging::ProtocolMessages::ITEM_RELEASED
NoteMessaging::ProtocolMessages::DEVICE_ATTACHED
NoteMessaging::ProtocolMessages::DEVICE_DETACHED
NoteMessaging::ProtocolMessages::DEVICE_DISCONNECTED

// Keys
NoteMessaging::Keys::EVENT
NoteMessaging::Keys::CMD
NoteMessaging::Keys::DEVICE_ID
NoteMessaging::Keys::CORRELATION_ID
NoteMessaging::Keys::STATUS
NoteMessaging::Keys::ITEMS
NoteMessaging::Keys::ERROR
NoteMessaging::Keys::MSG
```

---

## See Also

- [Architecture Overview](architecture.md)
- [NoteUSB Module Documentation](../NoteUSB/docs/device_acquisition_api.md)
- [Protocol Wire Format](../protocol_wire_format.md)