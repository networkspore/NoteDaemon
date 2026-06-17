NoteDaemon — Secure IO Daemon (Linux)
=======================================

NoteDaemon provides exclusive access to input devices and encrypted file storage,
bypassing OS-level input systems for secure password entry and other
security-critical scenarios.

Features
--------
- Exclusive Device Access: Detaches kernel drivers to prevent input interception
- Protocol Negotiation: Multiple modes (RAW, PARSED, ENCRYPTED)
- End-to-End Encryption: Diffie-Hellman key exchange + AES-256-GCM
- Secure Buffer Handling: Automatic zeroing of sensitive data
- NoteFile Service: API-key authenticated, zone-isolated file storage
- Modular Architecture: Loadable .so modules for extensibility
- WebRTC Transport: Optional data channel support via libdatachannel

Architecture
------------

```
┌──────────────────────────────────────────────────────────────┐
│                    Two-Socket Model                          │
│                                                              │
│  Management Socket (Unix/TCP)         Data Channel (any)     │
│  ┌─────────────────────────────┐     ┌────────────────────┐  │
│  │ HELLO, AUTH, QUERY          │     │ DEVICE_HANDSHAKE   │  │
│  │ CLAIM, RELEASE, GET_FILE    │     │ → streaming events │  │
│  │ PUT_FILE, DELETE_FILE       │     │ → file bytes       │  │
│  │ Admin + client management   │     │ → WebRTC, TCP,     │  │
│  │                             │     │   Unix socket      │  │
│  └─────────────────────────────┘     └────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### NoteFile Service — Three-Layer Auth

```
┌──────────────────────────────────────────────────────────────┐
│  TLS Server Key  (Ed25519, for SSL transport)                │
│  /etc/netnotes/server.key  (perm 0600, daemon-owned)         │
├──────────────────────────────────────────────────────────────┤
│  Admin API Key  (SHA-256 hashed, one-time setup)             │
│  /etc/netnotes/admin.key  (perm 0600)                        │
│  └─ Manages clients: add/remove/list/change API keys        │
├──────────────────────────────────────────────────────────────┤
│  Client Registry  (API key hashes per client)                │
│  /etc/netnotes/clients.dat  (perm 0600)                      │
│  └─ client_id → { api_key_hash, created_at }                │
├──────────────────────────────────────────────────────────────┤
│  Per-Client Zones  (Java NotePath-style ledger)              │
│  /var/netnotes/data/<client_id>/.ledger                      │
│  └─ Hierarchical path mapping (no encryption at rest)        │
└──────────────────────────────────────────────────────────────┘
```

Key design: data is **plaintext at rest**, protected by OS file permissions
(chmod 0600). Per-file server-side encryption is avoided — the server
has the keys, so encryption doesn't add real security. Instead:
- **Transport security**: TLS/Unix socket peer credentials
- **Authentication**: API key hashing with salt, constant-time comparison
- **Authorization**: Per-client directory + ledger zones
- **Disk protection**: Strict file permissions on all sensitive files

### Management Socket Handlers

| Message              | Purpose                                              |
|----------------------|------------------------------------------------------|
| `set_admin_api_key`  | Set admin API key (first boot, one-time)             |
| `admin_auth`         | Authenticate as admin                                |
| `add_client`         | Create a new client with their API key               |
| `remove_client`      | Remove a client and all their data                   |
| `list_clients`       | List all client IDs                                  |
| `client_auth`        | Authenticate as a client                             |
| `get_file`           | Read a file (inline, small data)                     |
| `put_file`           | Write a file (inline, small data)                    |
| `delete_file`        | Delete a file                                        |
| `open_file_stream`   | Open a streaming session (large data, any transport) |
| `close_stream`       | Close a streaming session                            |

### File Access — Two Options

**Inline** (management socket, single round-trip):
```
put_file  {client_id, path, data}  →  file_written
```
Use for configs, settings, small objects (<1MB).

**Stream** (data channel, zero buffering):
```
open_file_stream {client_id, path, mode} → stream_opened
→ connect device socket with "stream:<client_id>:<id>"
→ data flows in 64KB chunks
```
Use for large files, real-time data, WebRTC transport.

### Protocol

Full protocol specification with examples:
[NoteBytes Wire Protocol Format](protocol_wire_format.md)

### Client Usage

See the [Protocol doc](protocol_wire_format.md#client-usage-examples) for
Python and Java client examples covering the full lifecycle:
admin setup → client creation → auth → file write/read → streaming.

### Modules

Loadable .so modules extend the daemon:
- **note_usb** — USB HID device management (libusb)
- Custom modules via `IModule` interface

Modules declare a channel type ("unix", "tcp", "webrtc") for their
data plane. Signaling goes through the management socket.

Config
------
Place config file in your home directory: `~/.netnotes/config` (key=value format)
See [config-example](config-example).

Installation
------------

Quick install:
```bash
curl -fsSL https://raw.githubusercontent.com/networkspore/NoteDaemon/master/download-install.sh -o install.sh
less install.sh   # Review the script
sudo bash install.sh
```

Manual build:
```bash
sudo bash build.sh --install
```

Requirements: daemon and client must be part of the `netnotes` group with
adequate privileges to access the socket and USB devices.
See [udev rules](99-netnotes.rules).

Scripts
-------
- [Download install](download-install.sh)
- [Builder bash](build.sh)
- [Configuration bash](setup-netnotes.sh)
- [Uninstall](uninstall-netnotes.sh)
