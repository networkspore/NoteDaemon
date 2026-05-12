# NoteDaemon Modular Refactor

## Current Architecture

```
main.cpp
├── NoteDaemon (monolithic)
│   ├── LinuxRequirements - USB access validation
│   ├── SimpleConfigParser - key=value config parsing
│   ├── DaemonConfig - configuration management
│   └── Main event loop (select-based)
│
└── DeviceSession (per-client)
    ├── libusb context
    ├── Handler maps (unordered_map for O(1) dispatch)
    ├── Streaming threads (USB-specific)
    ├── Device registry (USB-specific)
    ├── Capability registry (bitflags)
    └── NoteBytes protocol handling
```

## Target Architecture

### Core Framework (NoteDaemon Core)

```
NoteDaemon Core/
├── ModuleLoader              - Runtime loading of shared libraries (.so)
├── IModule                   - Interface all modules implement
├── ModuleRegistry            - Tracks loaded modules by name/ID
├── ModuleRoutingRegistry     - Routes messages to correct module (Level 1)
├── HandlerRegistry           - Per-module device-level handlers (Level 2)
├── ErrorCollector            - Pull-based error collection from modules
├── ConfigManager             - Module-specific configuration loading
├── EncryptionAPI             - Core encryption service for modules
└── NoteDaemon                - Main application (thin wrapper)
```

### Module Structure (Independent Project)

Each module is an independent project that can be built and maintained separately:

```
~/Dev/notes/NoteUSB/           # Independent module project
├── CMakeLists.txt             # Builds note_usb.so + monitor binary
├── src/
│   ├── module.cpp             # IModule implementation
│   ├── device_handler.cpp    # NoteBytes message handlers
│   ├── device_monitor.cpp    # Device monitor wrapper
│   └── ...
└── monitor/
    └── main.cpp              # The actual monitor binary
```

---

## Design Decisions

### 1. Module Discovery Path

**Decision**: `/etc/netnotes/modules/<module_name>/`
**Structure**:
```
/etc/netnotes/modules/
├── note_usb/
│   ├── config.json           # Module configuration
│   ├── note_usb.so          # Compiled module
│   ├── monitor-note_usb     # Device monitor binary (module-specific)
│   └── [module-specific files]
│
├── note_ai_rpg/
│   ├── config.json
│   ├── note_ai_rpg.so
│   └── tools/
│
└── [future modules]
```

### 2. Two-Level Routing

**Decision**: Core routes to module, module handles device-specific routing

**Level 1 - Module Routing (Core)**:
- Core registry maps: message_type → module_id
- Example: "claim_item" → "note_usb", "ai_query" → "note_ai_rpg"
- Core doesn't need to know about devices, only which module handles what

**Level 2 - Device Routing (Module)**:
- Each module has its own HandlerRegistry
- Module routes to specific device based on device_id in message
- No prefixing needed - modules have separate namespaces

**Message Flow**:
```
Client Message
    ↓
Core (ModuleRoutingRegistry)
    → lookup "claim_item" → module_id = "note_usb"
    → forward to note_usb module
    ↓
NoteUSB Module (HandlerRegistry)
    → get device_id from message = "1:2"
    → lookup handler for device "1:2"
    → execute handler
    ↓
Response back to client
```

### 3. Module Interface

```cpp
class IModule {
public:
    virtual ~IModule() = default;

    // ===== Identity =====
    virtual std::string_view name() const = 0;           // e.g., "note_usb"
    virtual std::string_view version() const = 0;        // e.g., "1.0.0"
    virtual std::string_view description() const = 0;

    // ===== Lifecycle =====
    virtual Error init(const Json& config) = 0;
    virtual Error start() = 0;
    virtual Error stop() = 0;
    virtual void shutdown() = 0;

    // ===== Health Check (called after load) =====
    virtual Error check_health(const std::string& core_api_version) = 0;

    // ===== Capabilities =====
    virtual cpp_int capabilities() const = 0;

    // ===== Message Types this module handles =====
    virtual std::vector<std::string> get_handled_message_types() = 0;

    // ===== Handler Registry (for device-level routing) =====
    virtual HandlerRegistry& get_handler_registry() = 0;

    // ===== Error Collection (pull-based, thread-safe) =====
    virtual void collect_errors(std::vector<Error>& errors) = 0;

    // ===== Cleanup =====
    virtual void cleanup() = 0;
};
```

### 4. Module Loading Failure Handling

**Decision**: Configurable via core config flag

**Core Config** (`/etc/netnotes/netnotes.conf`):
```ini
# Module loading
modules.directory=/etc/netnotes/modules
modules.strict_load=true    # true = fail on any module load failure
modules.health_check=true  # poll modules after load to verify health
```

**Loading Flow**:
1. Core discovers modules from `modules.directory`
2. Loads each .so file, calls factory to create IModule
3. If `health_check=true`: calls `module->check_health(core_version)`
4. If health check fails:
   - If `strict_load=true`: fail daemon startup
   - If `strict_load=false`: skip module, continue with others
5. If `health_check=false`: trust module is healthy

### 5. Configuration

**Main Config** (`/etc/netnotes/netnotes.conf`) - Core only:
```ini
socket.path=/run/netnotes/notedaemon.sock
socket.group=netnotes
log.level=info

# Module settings
modules.directory=/etc/netnotes/modules
modules.strict_load=true
modules.health_check=true
```

**Module Config** (`/etc/netnotes/modules/<name>/config.json`):
```json
{
  "name": "note_usb",
  "version": "1.0.0",
  "description": "USB/HID device support for NoteDaemon",
  "api_version": "1.0",
  "dependencies": [],
  "device_monitor": {
    "enabled": true,
    "binary": "monitor-note_usb"
  },
  "settings": {
    "discovery_interval_ms": 1000,
    "auto_detach_kernel": true
  }
}
```

### 6. Device Monitor

**Decision**: Module-specific, not managed by core

The device monitor is specific to certain modules (like LibUSB for reattaching kernel drivers). The core doesn't manage it - it just provides the daemon PID to the module.

**Module's responsibility**:
- Module decides if it needs a device monitor
- Module creates/starts the monitor in `start()`
- Core passes daemon PID to module during start()
- Monitor survives `stop()` - it runs until it verifies resources are freed

**NoteUSB Monitor**:
- Located at: `/etc/netnotes/modules/note_usb/monitor-note_usb`
- Receives daemon PID at startup
- Waits for daemon to terminate
- On termination, reattaches kernel drivers for all claimed devices
- Exits only after verifying all resources freed

### 7. Encryption API

**Decision**: Core provides encryption service, modules use per-device API

```cpp
// Core encryption API available to all modules
class IEncryptionProvider {
public:
    virtual ~IEncryptionProvider() = default;

    // Initialize encryption for a specific device (no handshake)
    virtual int init_device(const std::string& device_id,
                           const std::vector<uint8_t>& key) = 0;

    virtual bool is_encrypted(const std::string& device_id) const = 0;

    // Encrypt/decrypt data for device
    virtual bool encrypt(const std::string& device_id,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext) = 0;

    virtual bool decrypt(const std::string& device_id,
                        const std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& plaintext) = 0;

    virtual void remove_device(const std::string& device_id) = 0;
};

// Modules call: get_encryption_provider().encrypt(device_id, ...)
```

**Note**: No handshake/negotiation involved - this is simple per-device encrypt/decrypt, not SSL-like.

### 8. Error Handling

**Decision**: Collect-and-pull approach

```cpp
struct Error {
    uint32_t code;           // From note_messaging.h ErrorCodes
    std::string description;
    std::string module;      // Which module generated the error
    uint64_t timestamp;
};

// Modules implement: void collect_errors(std::vector<Error>& errors)
// Core polls periodically or on demand
```

---

## Implementation Phases

### Phase 1: Core Framework

**Goal**: Create the modular foundation

**Files to Create**:
```
include/module_framework/
├── error.h              # Error struct
├── imodule.h           # IModule interface
├── module_loader.h     # dlopen/LoadLibrary wrapper
├── module_registry.h   # Track loaded modules
├── handler_registry.h  # Per-module handler registry
├── error_collector.h   # Pull-based errors
├── config_manager.h   # Load module configs
└── encryption_api.h   # Core encryption for modules

src/core/
├── module_loader.cpp
├── module_registry.cpp
├── handler_registry.cpp
├── error_collector.cpp
├── config_manager.cpp
└── encryption_api.cpp
```

**Modify**:
- `CMakeLists.txt` - Add core to build
- `src/main.cpp` - Use ModuleLoader, implement two-level routing

### Phase 2: NoteUSB Module (Independent Project)

**Goal**: Extract USB handling to independent module

**Project**: `~/Dev/notes/NoteUSB/`

**Files**:
```
NoteUSB/
├── CMakeLists.txt              # Build note_usb.so + monitor-note_usb
├── config.json                 # Module config
├── src/
│   ├── module.cpp              # IModule implementation
│   ├── device_handler.cpp      # NoteBytes handlers (CLAIM, RELEASE, etc.)
│   ├── device_monitor.cpp      # Fork/exec monitor binary
│   ├── streaming_thread.cpp    # HID streaming
│   └── device_discovery.cpp    # USB discovery
└── monitor/
    ├── CMakeLists.txt
    └── main.cpp                 # The actual monitor binary
```

**Install to**:
- `/etc/netnotes/modules/note_usb/config.json`
- `/etc/netnotes/modules/note_usb/note_usb.so`
- `/etc/netnotes/modules/note_usb/monitor-note_usb`

### Phase 3: Integration & Testing

**Goal**: Verify modules load and work with core

- NoteDaemon discovers and loads NoteUSB
- Core routes USB messages to NoteUSB module
- Device discovery, claim, release work
- Device monitor starts and survives daemon stop

### Phase 4: Encryption Implementation

**Goal**: Implement currently stubbed encryption

- Implement encryption_api.cpp
- NoteUSB uses encryption API for per-device encryption
- Test: encrypt/decrypt works correctly

---

## File Structure After Refactor

```
NoteDaemon/
├── CMakeLists.txt              # MODIFIED - build core framework
├── include/
│   ├── module_framework/       # NEW - core framework headers
│   │   ├── error.h
│   │   ├── imodule.h
│   │   ├── module_loader.h
│   │   ├── module_registry.h
│   │   ├── handler_registry.h
│   │   ├── error_collector.h
│   │   ├── config_manager.h
│   │   └── encryption_api.h
│   │
│   ├── note_messaging.h        # EXISTING
│   ├── notebytes.h           # EXISTING
│   ├── capability_registry.h # EXISTING
│   └── ...
│
└── src/
    ├── core/                   # NEW - core implementation
    │   ├── module_loader.cpp
    │   ├── module_registry.cpp
    │   ├── handler_registry.cpp
    │   ├── error_collector.cpp
    │   ├── config_manager.cpp
    │   └── encryption_api.cpp
    │
    ├── main.cpp               # MODIFIED - load modules, route messages
    └── ...

# Independent Module Projects (built separately):
~/Dev/notes/NoteUSB/            # USB/HID module
├── CMakeLists.txt
├── src/
│   ├── module.cpp
│   └── ...
├── monitor/
│   └── ...
└── config.json

~/Dev/notes/NoteAI/            # Future: AI-RPG module
├── CMakeLists.txt
├── src/
│   └── ...
└── config.json
```

---

## Configuration Summary

### Core Config (`/etc/netnotes/netnotes.conf`)

```ini
# Socket
socket.path=/run/netnotes/notedaemon.sock
socket.group=netnotes

# Logging
log.level=info

# Module loading
modules.directory=/etc/netnotes/modules
modules.strict_load=true
modules.health_check=true
```

### NoteUSB Module Config (`/etc/netnotes/modules/note_usb/config.json`)

```json
{
  "name": "note_usb",
  "version": "1.0.0",
  "description": "USB/HID device support for NoteDaemon",
  "api_version": "1.0",
  "dependencies": [],
  "device_monitor": {
    "enabled": true,
    "binary": "monitor-note_usb"
  },
  "settings": {
    "discovery_interval_ms": 1000,
    "auto_detach_kernel": true
  }
}
```

---

## Notes from Codebase Exploration

- NoteDaemon uses `boost::multiprecision::cpp_int` for capability bitflags
- Handler signature: `std::function<void(const NoteBytes::Object&)>`
- Uses syslog for logging
- Current error handling is exception-based (differs from module design)
- Configuration is key=value format, extensible with sections
- Main loop is select()-based, single-threaded
- DeviceSession is created per-client connection
- Process monitor exists as separate fork - will become NoteUSB's monitor

---

## Resolved Questions

| Question | Resolution |
|----------|------------|
| Module discovery path | `/etc/netnotes/modules/<name>/` with config.json + .so at root |
| Handler registry | Each module has its own registry, core pulls/merges by message type |
| Routing design | Two-level: Core routes to module, module handles device |
| Module failure handling | Configurable via `modules.strict_load` flag |
| Device monitor | Module-specific, not managed by core, survives stop() |
| Module project structure | Independent projects, built separately (e.g., ~/Dev/notes/NoteUSB/) |
| Encryption | Core provides encrypt/decrypt API, no handshake |
| Version compatibility | Core provides version to module during health check |

---

## Hot Loading

**Status**: NOT A REQUIREMENT
**Note**: Hot-loading modules at runtime without restart is not planned for this refactor.