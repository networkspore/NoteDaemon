# Architecture Update - Module ID Routing and Error Code Standardization

## Date: 2024-05-10

## Overview

This document describes the architectural changes made to align the C++ daemon implementation with the client-side expectations, including module ID routing and standardized error codes.

---

## Key Architectural Shifts

### 1. Socket = Device (No Correlation ID)

**Before:**
- Each message included a `correlation_id` to match requests to responses
- Multiple devices could be claimed per socket
- Required complex request-response matching

**After:**
- Each socket connection owns exactly one device
- No need for `correlation_id` in protocol
- Socket itself identifies the device context
- Simpler request-response matching

**Impact:**
- Removed `correlation_id` from all claim/release messages
- Responses no longer include correlation_id
- Simplified protocol and error handling

### 2. Module ID for Routing

**Before:**
- Message routing was done via legacy message type matching
- DeviceSession handled all device logic

**After:**
- `module_id` field in routed messages selects which module handles the request
- Each module has its own device registry
- Cleaner separation of concerns

**Impact:**
- Messages include `module_id` for routing
- Module-specific handlers in HandlerRegistry
- Modular device management

---

## Error Code Standardization

### New Error Codes Added

| Code | Name | Description |
|------|------|-------------|
| 10 | DEVICE_NOT_FOUND | Device doesn't exist |
| 11 | ITEM_NOT_AVAILABLE | Device already claimed |
| 16 | ALREADY_RELEASED | Device was already released |
| 24 | NOT_OWNER | Client is not the owner of the device |

### Updated Error Codes

| Code | Name | Description |
|------|------|-------------|
| 20 | PERMISSION_DENIED | Cannot open device / permission issue |
| 23 | ALREADY_CLAIMED | Device already claimed by this client |

### Removed Error Codes

- All JAVA-specific aliases (ITEM_NOT_FOUND_JAVA, etc.) removed
- C++ is the source of truth; Java will be updated to match

### Error Code Usage

```cpp
// Claim device - error codes
DEVICE_NOT_FOUND (10)       // Device doesn't exist
ITEM_NOT_AVAILABLE (11)     // Device already claimed
PERMISSION_DENIED (20)      // Cannot open device
NOT_OWNER (24)              // Client not the owner

// Release device - error codes
DEVICE_NOT_FOUND (10)       // Device not claimed
NOT_OWNER (24)              // Client not the owner
ALREADY_RELEASED (16)       // Device was already released
```

---

## Device Ownership Tracking

### Implementation

Each claimed device now tracks the owner process ID:

```cpp
struct USBDeviceDescriptor {
    std::string device_id;
    uint16_t vendor_id = 0;
    uint16_t product_id = 0;
    int interface_number = 0;
    bool kernel_driver_attached = false;
    libusb_device_handle* handle = nullptr;
    pid_t owner_pid = 0;  // NEW: Tracks who owns this device
};
```

### Ownership Check

When a client tries to release a device, ownership is verified:

```cpp
// In NoteUSBSession::release_device()
if (device_->owner_pid != client_pid_) {
    return Error::from_code(ErrorCodes::NOT_OWNER,
                            "Not owner of device: " + device_id);
}
```

### Benefits

1. **Security**: Prevents unauthorized device release
2. **State Tracking**: Clear ownership for crash recovery
3. **Debugging**: Easy to identify which client owns which device

---

## Module Routing

### Message Structure

All routed messages now include `module_id`:

```json
{
  "event": "cmd",
  "cmd": "claim_item",
  "module_id": "note_usb",
  "device_id": "1:2"
}
```

### Handler Registration

Modules register their handlers in the HandlerRegistry:

```cpp
registry.register_module_handler("note_usb", "claim_item",
    [this](const NoteBytes::Object& msg) {
        handle_claim_device(msg);
    });
```

### Routing Flow

1. Client sends routed message with `module_id`
2. NoteDaemon main.cpp extracts `module_id`
3. Looks up module in ModuleRegistry
4. Forwards message to module's handler registry
5. Handler processes and sends response

---

## Protocol Changes

### Claim Item Request

**Before:**
```json
{
  "event": "cmd",
  "cmd": "claim_item",
  "device_id": "1:2",
  "correlation_id": "uuid-123"
}
```

**After:**
```json
{
  "event": "cmd",
  "cmd": "claim_item",
  "module_id": "note_usb",
  "device_id": "1:2"
}
```

### Claim Item Response

**Before:**
```json
{
  "event": "item_claimed",
  "device_id": "1:2",
  "correlation_id": "uuid-123",
  "status": "claimed"
}
```

**After:**
```json
{
  "event": "item_claimed",
  "device_id": "1:2",
  "status": "claimed"
}
```

### Release Item Request

**Before:**
```json
{
  "event": "cmd",
  "cmd": "release_item",
  "device_id": "1:2",
  "correlation_id": "uuid-456"
}
```

**After:**
```json
{
  "event": "cmd",
  "cmd": "release_item",
  "module_id": "note_usb",
  "device_id": "1:2"
}
```

### Release Item Response

**Before:**
```json
{
  "event": "item_released",
  "device_id": "1:2",
  "correlation_id": "uuid-456",
  "status": "success"
}
```

**After:**
```json
{
  "event": "item_released",
  "device_id": "1:2",
  "status": "success"
}
```

---

## Implementation Details

### Files Modified

1. **include/note_messaging.h**
   - Added DEVICE_NOT_FOUND = 10
   - Added NOT_OWNER = 24
   - Added ALREADY_RELEASED = 16
   - Removed all JAVA-specific aliases

2. **include/note_usb/device_handler.h**
   - Added `pid_t owner_pid` to USBDeviceDescriptor

3. **src/note_usb_session.cpp**
   - Set `device_->owner_pid = client_pid_` on claim
   - Added ownership check in release_device()

4. **include/device_session.h**
   - Updated error codes to use DEVICE_NOT_FOUND

5. **tests/device_claim_release_test.cpp**
   - Updated test expectations

---

## Benefits of Changes

### For C++ Daemon

1. **Simpler Protocol** - No correlation_id needed
2. **Clearer Ownership** - Each device has a clear owner
3. **Better Security** - Cannot release device you don't own
4. **Modular Design** - Module ID routing for extensibility

### For Java Client

1. **Consistent API** - Single error code system
2. **Simpler Code** - No correlation_id tracking
3. **Better Debugging** - Clear error codes

---

## Migration Guide

### For Java Client Developers

1. **Remove correlation_id** from all claim/release messages
2. **Add module_id** to routed messages (if using routed protocol)
3. **Update error code handling**:
   - ITEM_NOT_FOUND → DEVICE_NOT_FOUND (10)
   - NOT_OWNER → NOT_OWNER (24)
   - ALREADY_RELEASED → ALREADY_RELEASED (16)

4. **Update response handling**:
   - Remove correlation_id from response parsing

### For C++ Daemon Users

1. **Update error code constants** to use the new codes
2. **Test ownership checks** on device release
3. **Verify module routing** works with module_id

---

## Testing

### Unit Tests

All existing tests pass with updated error codes:
- `device_claim_release_test.cpp` - Updated to use new codes
- `device_session_test.cpp` - Tests state transitions
- `module_registry_test.cpp` - Tests module management

### Integration Tests

- Claim device with correct owner → Success
- Claim device with wrong owner → NOT_OWNER error
- Release unclaimed device → DEVICE_NOT_FOUND error
- Release already released device → ALREADY_RELEASED error

---

## Future Work

1. **Complete module_id integration** - Ensure all routed messages use module_id
2. **Update Java client** - Migrate to new error codes and remove correlation_id
3. **Add module discovery** - GET_MODULES command to list available modules
4. **Add module-specific discovery** - DISCOVER_MODULES_BY_MODULE_ID command

---

## See Also

- [Device Acquisition API](device_acquisition_api.md)
- [Client-Daemon Analysis](client_daemon_analysis.md)
- [NoteUSB Architecture](../NoteUSB/docs/architecture.md)