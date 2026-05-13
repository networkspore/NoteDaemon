# Multi-Socket Architecture — Updated Analysis

## 1. What This Changes

The previous analysis flagged the question of "who owns the socket" as the biggest
unresolved issue. The answer is now clear:

- **One management socket per IODaemon client** — owned by the core, never handed
  to any module. This socket carries: `query_devices`, `get_modules`,
  `claim_device` requests, `release_device` requests, and all responses to those.
- **One device socket per claimed device** — handed off to the module after claim
  is acknowledged. This socket carries only the device's event stream (raw/parsed
  HID data, etc.) and belongs exclusively to that device for the lifetime of the
  claim. No extra framing hops, no shared read path.

This is architecturally correct and resolves the routing ambiguity. The core's
main loop keeps the management socket. Modules get device sockets. The commented-out
routing code in `main.cpp` belongs exactly where it was — it just needs to be
uncommented and extended for the management socket path.

---

## 2. The Two-Socket Model in Detail

```
IODaemon (Java)
├── management_socket (fd_0)     ←→   NoteDaemon core main_loop
│   send: query_devices               routes: QueryRouter.processQuery()
│   send: get_modules                 routes: handle_get_modules()
│   send: claim_device                routes: module.handle_client(new_fd)
│   send: release_device              routes: module.cleanup_client()
│   recv: query_result
│   recv: module_list
│   recv: device_claimed (+ new fd info)
│   recv: device_list / hotplug events
│
├── device_socket_1 (fd_1)       ←→   NoteUSBModule (owns fd_1 entirely)
│   recv: raw/parsed HID events        module read loop, zero extra hops
│
└── device_socket_2 (fd_2)       ←→   NoteUSBModule (owns fd_2 entirely)
    recv: raw/parsed HID events
```

The management socket stays in the core forever. The device sockets are never
read by the core after hand-off.

---

## 3. How Claim Works Across Sockets

The claim flow must allocate the device socket. There are two clean approaches:

### Option A — Client opens a second connection proactively

1. Client sends `claim_device { session_id, device_id, mode }` on management socket
2. Client *simultaneously* opens a second TCP/Unix socket connection to the daemon
3. Client sends a short `device_handshake { session_id, device_id }` on that
   second connection to bind it
4. Daemon core, on receiving the handshake, calls `module->handle_client(new_fd)`
5. Daemon sends `device_claimed` on management socket to confirm

The client must open the second socket before or immediately after sending the claim
request, because the daemon will respond quickly. Race conditions are avoided by
including `session_id + device_id` in the handshake so the daemon can match them.

### Option B — Daemon creates a socketpair and passes the fd (Linux only)

1. Client sends `claim_device` on management socket
2. Daemon creates a `socketpair()` internally
3. Daemon sends `device_claimed { fd_token }` back on management socket,
   passing one end of the pair using `SCM_RIGHTS` (Unix fd passing)
4. Client receives the fd directly — no second `connect()` needed
5. Module gets the other end via `handle_client()`

Option B is more elegant (no race window, no second connect), but requires the
Java client to use JNI or `ProcessHandle`/native calls to receive ancillary data
from a Unix socket, which is non-trivial.

**Recommendation**: Use Option A for now. The second socket path is simple, the
`device_handshake` message is small, and the race window is acceptable since the
client controls both sockets.

---

## 4. C++ Daemon Changes

### 4.1 `main.cpp` — Restore the Management Socket Read Loop

The currently-commented routing code in `main_loop()` / `handle_client_message()`
is exactly the right place for management socket handling. Uncomment and extend it:

```cpp
void handle_management_message(int client_fd,
                               const NoteBytes::Object& message) {
    // Determine command type
    auto* cmd_val = message.get(NoteMessaging::Keys::CMD);
    if (!cmd_val) return;

    if (*cmd_val == NoteMessaging::ProtocolMessages::QUERY_DEVICES) {
        auto* query_val = message.get(NoteMessaging::Keys::QUERY);
        if (query_val) {
            auto result = query_router_.processQuery(
                query_val->as_object(), module_registry_);
            result.add(NoteMessaging::Keys::EVENT,
                       NoteMessaging::ProtocolMessages::QUERY_RESULT);
            write_to_fd(client_fd, result);
        }
    }
    else if (*cmd_val == NoteMessaging::ProtocolMessages::GET_MODULES) {
        handle_get_modules(client_fd);
    }
    else if (*cmd_val == NoteMessaging::ProtocolMessages::CLAIM_DEVICE) {
        // Do NOT handle here — this arrives on the device socket
        // (see §4.2). Flag as unexpected if received on management socket.
        syslog(LOG_WARNING, "claim_device received on management socket");
    }
    // ... other management commands
}
```

Add a `QueryRouter` member to `NoteDaemonApp`:

```cpp
class NoteDaemonApp {
    // ...existing members...
    QueryRouter query_router_;  // constructed after modules are loaded
};
```

### 4.2 `main.cpp` — Device Socket Path (Already Works)

When the daemon `accept()`s a new connection, it reads the first message. If it
is a `device_handshake`, it extracts `session_id + device_id`, looks up which
module owns that device, and calls `module->handle_client(new_fd, client_pid)`.
The module then owns `new_fd` exclusively.

```cpp
void dispatch_new_connection(int client_fd) {
    NoteBytes::Object first_msg = read_first_message(client_fd);
    auto* cmd = first_msg.get(NoteMessaging::Keys::CMD);

    if (cmd && *cmd == NoteMessaging::ProtocolMessages::DEVICE_HANDSHAKE) {
        // Device socket path — route to owning module
        std::string device_id = /* extract from message */;
        std::string module_id = routing_registry_.lookup_module_for_device(device_id);
        if (auto* mod = module_registry_.get(module_id)) {
            mod->handle_client(client_fd, client_pid);
            // mod now owns client_fd entirely — do NOT read from it again here
        }
    } else {
        // Management socket path — keep in core read loop
        run_management_loop(client_fd);
    }
}
```

This means `routing_registry_` needs a second lookup: not just `message_type →
module_id` but also `device_id → module_id` (which module currently holds that
claimed device). `DeviceHandler` in NoteUSB can answer this, but the lookup needs
to go through a core-visible interface.

One clean option: when a device is successfully claimed by a module, the module
calls back into a core-provided registry:

```cpp
class DeviceOwnershipRegistry {
public:
    void register_device(const std::string& device_id,
                         const std::string& module_id);
    void unregister_device(const std::string& device_id);
    std::string lookup_module(const std::string& device_id) const;
};
```

This lives in the core and is passed to modules via `init()` config or a dedicated
setter. Modules call it on successful `claim_device` and on `release_device`.

---

## 5. Java (IODaemon) Changes

### 5.1 Socket Management

`IODaemon` currently manages a single socket. It needs to manage a pool:

```
IODaemon
├── managementChannel : DaemonChannel   (single, persistent)
└── deviceChannels : Map<NoteBytes, DaemonChannel>
    (one per claimed device, keyed by device_id)
```

`DaemonChannel` wraps a single socket connection with its read loop. The
management channel's read loop routes incoming messages to handlers in `IODaemon`.
Each device channel's read loop routes events to the corresponding `ClaimedDevice`.

### 5.2 Claim Flow in Java

```java
// In IODaemon.claimDevice() (on daemon's executor):
public CompletableFuture<Void> claimDevice(
        NoteBytes sessionId, NoteBytes moduleId,
        NoteBytes deviceId, NoteBytes mode) {

    // 1. Open a new socket connection to the daemon
    DaemonChannel deviceChannel = openNewChannel();

    // 2. Store the channel before sending claim (avoid race)
    deviceChannels.put(deviceId, deviceChannel);

    // 3. Send device_handshake on the new channel to bind it
    deviceChannel.send(buildHandshake(sessionId, deviceId));

    // 4. Send claim_device on the management channel
    managementChannel.send(buildClaimRequest(sessionId, moduleId, deviceId, mode));

    // 5. Return future that completes when device_claimed arrives on mgmt channel
    CompletableFuture<Void> claimFuture = new CompletableFuture<>();
    pendingClaims.put(deviceId, claimFuture);
    return claimFuture;
}
```

### 5.3 `ClaimedDevice` — Attaches to Device Channel

Once `device_claimed` arrives on the management channel, `ClaimedDevice` is
given a reference to its `DaemonChannel`. The channel's read loop feeds events
directly to `ClaimedDevice.onCreateEvent()`. No IODaemon overhead, no shared queue.

```java
// On receiving device_claimed on management channel:
private void handleDeviceClaimed(NoteBytesMap map) {
    NoteBytes deviceId = map.get(Keys.DEVICE_ID);
    DaemonChannel channel = deviceChannels.get(deviceId);
    ClaimedDevice device = pendingClaimedDevices.remove(deviceId);

    // Wire channel to device — events flow directly
    channel.setMessageHandler(eventBytes -> device.onEvent(eventBytes));

    CompletableFuture<Void> pending = pendingClaims.remove(deviceId);
    if (pending != null) pending.complete(null);
}
```

### 5.4 Release Flow

Releasing a device:
1. Send `release_device` on the management channel
2. On receiving `device_released` on management channel, close the device channel
3. Remove from `deviceChannels` map

```java
public CompletableFuture<Void> releaseDevice(NoteBytes sessionId, NoteBytes deviceId) {
    managementChannel.send(buildReleaseRequest(sessionId, deviceId));

    CompletableFuture<Void> future = new CompletableFuture<>();
    pendingReleases.put(deviceId, future);
    return future;
}

private void handleDeviceReleased(NoteBytesMap map) {
    NoteBytes deviceId = map.get(Keys.DEVICE_ID);
    DaemonChannel channel = deviceChannels.remove(deviceId);
    if (channel != null) channel.close();

    CompletableFuture<Void> pending = pendingReleases.remove(deviceId);
    if (pending != null) pending.complete(null);
}
```

---

## 6. Query System Fit — Now Clean

With this model, the query system is straightforward:

- `query_devices` is a management socket command
- The core's management read loop dispatches it to `QueryRouter`
- `QueryRouter` fans out to modules (in-process, no socket hops)
- Response comes back on the management socket as `query_result`
- No conflict with device sockets whatsoever

The `QueryRouter` lives in `NoteDaemonApp`, receives a `ModuleRegistry&`, and is
called directly from `handle_management_message()`. The modules' device sockets are
completely unaffected.

---

## 7. Updated File Impact Summary

| File | Change |
|------|--------|
| `main.cpp` | Restore management read loop; add `dispatch_new_connection()` to distinguish management vs device handshake; add `QueryRouter` member |
| `note_messaging.h` | Add `DEVICE_HANDSHAKE`, `QUERY_DEVICES`, `QUERY_RESULT` protocol messages |
| `imodule.h` | Add `applyQuery()` + `getSupportedQueryFields()` (same as before) |
| New `DeviceOwnershipRegistry` | Core-level map of `device_id → module_id` for device socket routing |
| `query_router.h/.cpp` | New — unchanged from previous analysis |
| `query_filter.h/.cpp` | New — unchanged from previous analysis |
| `module.cpp` (NoteUSB) | Implement `applyQuery()`; call `DeviceOwnershipRegistry` on claim/release |
| `IODaemon.java` | Add `managementChannel` / `deviceChannels` distinction; claim opens new socket |
| `DaemonChannel.java` | **New** — wraps a single socket with its read loop and message handler |
| `ClaimedDevice.java` | Attach to `DaemonChannel` after claim; receive events directly |
| `QueryBuilder.java` | New — unchanged from previous analysis |
| `QueryResult.java` | New — unchanged from previous analysis |
| `IODaemonInterface.java` | Add `executeQuery()` — same as before |
| `ClientSession.java` | Add `queryDevices()` — same as before; claim now triggers socket open |
| `IODemo.java` | Fix Step 5 bug; update claim flow for two-socket model |
