# NoteBytes Wire Protocol Format

## Core Principle: Byte Predictability

All metadata is **exactly 5 bytes**: `[1-byte type][4-byte length in big-endian]`

This applies to **every** NoteBytes value, including integers where we know the length is 4 bytes. Predictability > efficiency.

---

## Basic Types

### Integer (sourceId = 42)
```
[0x03] [0x00] [0x00] [0x00] [0x04] [0x00] [0x00] [0x00] [0x2A]
  ^type  ^-------length=4------^   ^--------value=42--------^
  
Total: 9 bytes (5 metadata + 4 data)
```

### String ("hello")
```
[0x0B] [0x00] [0x00] [0x00] [0x05] [0x68] [0x65] [0x6C] [0x6C] [0x6F]
  ^type  ^-------length=5------^   ^---------"hello"-----------^
  
Total: 10 bytes (5 metadata + 5 data)
```

### Raw Bytes (3 bytes: [0xAA, 0xBB, 0xCC])
```
[0x00] [0x00] [0x00] [0x00] [0x03] [0xAA] [0xBB] [0xCC]
  ^type  ^-------length=3------^   ^-----data----^
  
Total: 8 bytes (5 metadata + 3 data)
```

---

## Complex Types

### Object (Key-Value Pairs)

Object body is sequence of pairs, wrapped in OBJECT metadata:

```
[0x0C] [0x00] [0x00] [0x00] [0x1E] <pairs...>
  ^type  ^-------length=30------^   ^--30 bytes of pairs--^
```

Example object: `{"type": 3, "msg": "ok"}`

```
Full breakdown:
[0x0C] [0x00] [0x00] [0x00] [0x1E]  ← OBJECT metadata (length=30)
  [0x0B] [0x00] [0x00] [0x00] [0x04] [0x74] [0x79] [0x70] [0x65]  ← key "type"
  [0x03] [0x00] [0x00] [0x00] [0x04] [0x00] [0x00] [0x00] [0x03]  ← value 3
  [0x0B] [0x00] [0x00] [0x00] [0x03] [0x6D] [0x73] [0x67]        ← key "msg"
  [0x0B] [0x00] [0x00] [0x00] [0x02] [0x6F] [0x6B]              ← value "ok"
  
Total: 5 + 30 = 35 bytes
```

### Array

Array body is sequence of values, wrapped in ARRAY metadata:

```
[0x0D] [0x00] [0x00] [0x00] [0x12] <values...>
  ^type  ^-------length=18------^   ^--18 bytes of values--^
```

---

## Protocol Messages

### 1. Control Message (Non-Routed)

Simple object sent directly:

```
Format: [OBJECT][length][pairs...]

Example: PING message
[0x0C] [0x00] [0x00] [0x00] [0x15]  ← OBJECT metadata
  [0x0B] [0x00] [0x00] [0x00] [0x04] [t][y][p][e]  ← key "type"
  [0x03] [0x00] [0x00] [0x00] [0x04] [0x00][0x00][0x00][0x10]  ← value 16 (TYPE_PING)
  
Total: 5 + 21 = 26 bytes
```

### 2. Routed Message (From Device)

Includes sourceId prefix to identify which device sent it:

```
Format: [INTEGER][0x00000004][sourceId][OBJECT or ENCRYPTED][length][data...]

Example: Key event from device with sourceId=42
[0x03] [0x00] [0x00] [0x00] [0x04] [0x00] [0x00] [0x00] [0x2A]  ← sourceId=42 (9 bytes)
[0x0C] [0x00] [0x00] [0x00] [0x28] <event object pairs...>      ← EVENT_KEY_DOWN object
  
Total: 9 + 5 + 40 = 54 bytes (varies by event data)
```

**Breaking down the sourceId:**
- `[0x03]` = INTEGER type
- `[0x00][0x00][0x00][0x04]` = length is 4 bytes (even though we know ints are 4 bytes!)
- `[0x00][0x00][0x00][0x2A]` = value 42 in big-endian

### 3. Encrypted Routed Message

Same structure, but event object is encrypted:

```
Format: [INTEGER][0x00000004][sourceId][ENCRYPTED][length][ciphertext...]

Example:
[0x03] [0x00] [0x00] [0x00] [0x04] [0x00] [0x00] [0x00] [0x2A]  ← sourceId=42
[0x1A] [0x00] [0x00] [0x00] [0x50] <80 bytes of AES-GCM ciphertext>
  ^ENCRYPTED type
  
Total: 9 + 5 + 80 = 94 bytes
```

---

## Reading Algorithm

### Reader pseudocode:
```
1. Read 5 bytes → parse metadata (type, length)
2. Read `length` bytes → parse data based on type
3. If type == INTEGER:
     - Convert 4 bytes big-endian to int32
4. If type == STRING:
     - Interpret bytes as UTF-8 string
5. If type == OBJECT:
     - Recursively read pairs until length consumed
6. If type == ENCRYPTED:
     - Decrypt, then parse decrypted bytes
```

### Writer pseudocode:
```
1. Determine type of data
2. Serialize data to bytes
3. Write metadata: [type][length]
4. Write data bytes
5. Repeat for nested structures
```

---

## C++ Implementation

### Writing with NoteBytesWriter

```cpp
NoteBytes::Writer writer(socket_fd);

// Write simple value
writer.write(NoteBytes::Value(42));  // Writes 9 bytes

// Write object
NoteBytes::Object obj;
obj.add("type", 16);  // TYPE_PING
writer.write(obj);    // Writes 5 + body_length bytes

// Write routed message
writer.write(NoteBytes::Value(sourceId));  // sourceId prefix
writer.write(event_obj);                   // event data
writer.flush();
```

### Reading with NoteBytesReader

```cpp
NoteBytes::Reader reader(socket_fd);

// Read value
NoteBytes::Value val = reader.read_value();

// Read object
NoteBytes::Object obj = reader.read_object();

// Read routed message
NoteBytes::Value sid = reader.read_value();
int32_t source_id = sid.as_int();
NoteBytes::Object event = reader.read_object();
```

---

## Key Differences from Other Protocols

### vs Protobuf/FlatBuffers:
- **Simpler**: No schema compilation needed
- **Self-describing**: Type info in every value
- **Predictable**: Fixed 5-byte metadata everywhere

### vs JSON:
- **Binary**: Much more compact
- **Typed**: Preserves int/string/bool types
- **Faster**: No parsing overhead

### vs MessagePack:
- **More verbose**: Always 5-byte metadata (MessagePack uses varint)
- **More predictable**: Can calculate exact sizes easily
- **Easier to debug**: Fixed format makes hex dumps clearer

---

## Common Patterns

### Pattern 1: Request/Response
```
Client → Server: [OBJECT] { "cmd": "discover" }
Server → Client: [OBJECT] { "type": "accept", "status": "ok" }
```

### Pattern 2: Device Streaming
```
Server → Client: [INTEGER][sourceId][OBJECT] { event... }
Server → Client: [INTEGER][sourceId][OBJECT] { event... }
Server → Client: [INTEGER][sourceId][OBJECT] { event... }
```

### Pattern 3: Batched Events
```
Server → Client: [INTEGER][sourceId][ARRAY]
                   [OBJECT] { event1... }
                   [OBJECT] { event2... }
                   [OBJECT] { event3... }
```

---

## Encryption Note

When encryption is active:
1. Event object is serialized WITH its metadata header
2. Entire packet (metadata + data) is encrypted
3. Encrypted bytes are wrapped in ENCRYPTED type
4. Result maintains same structure: `[sourceId][ENCRYPTED][length][ciphertext]`

This means the encryption is **transparent** to the protocol structure.

---

## NoteFile Service Protocol

### Authentication Model

The NoteFile service uses a **two-tier API key system**:

```
/var/netnotes/data/
├── clients/
│   ├── alice/
│   │   ├── .auth         ← hash of alice's API key
│   │   ├── .ledger       ← path mapping ledger
│   │   ├── a1b2...dat    ← actual files
│   │   └── c3d4...dat
│   └── bob/
│       └── ...
```

**Admin API key** (`/etc/netnotes/admin.key`):
- Set on first boot via `set_admin_api_key`
- Used to manage clients: `add_client`, `remove_client`, `list_clients`
- One-time setup — stored as SHA-256 hash with random salt

**Client API keys** (`data/clients/<id>/.auth`):
- Created by admin via `add_client {client_id, api_key}`
- Each client gets their own directory (zone)
- Authentication is per-client: `client_auth {client_id, api_key}`
- No central registry — client existence IS directory existence

---

### Lifecycle: Setup → Auth → File Ops

```
── FIRST BOOT ─────────────────────────────────────────────────────

Admin setup (once):
  → set_admin_api_key {api_key: "sk-admin-..."}
  ← {event: "admin_api_key_set", status: "ok"}

Create clients:
  → admin_auth {api_key: "sk-admin-..."}
  ← {event: "admin_auth_result", session_id: "..."}

  → add_client {client_id: "alice", api_key: "sk-alice-..."}
  ← {event: "client_added", status: "ok"}
  → add_client {client_id: "bob",   api_key: "sk-bob-..."}
  ← {event: "client_added", status: "ok"}

── CLIENT OPERATIONS ──────────────────────────────────────────────

Client authenticates:
  → client_auth {client_id: "alice", api_key: "sk-alice-..."}
  ← {event: "client_auth_result", status: "ok", session_id: "..."}

Now the client can access files in their zone (data/clients/alice/*).
```

---

### Inline File Operations (Management Socket)

For small files (configs, settings, small objects).
The entire NoteBytes::Object is serialized inline in one round-trip.

**Write a file:**
```
→ {event: "put_file", client_id: "alice",
     path: "apps/config/settings",
     data: <NoteBytes::Object serialized>}
← {event: "file_written", status: "ok"}
```

The server:
1. Resolves `apps/config/settings` in alice's ledger → finds/creates `uuid.dat`
2. Writes the Object bytes directly to `data/clients/alice/uuid.dat`
3. Returns success

**Read a file:**
```
→ {event: "get_file", client_id: "alice",
     path: "apps/config/settings"}
← {event: "file_content", client_id: "alice",
     path: "apps/config/settings",
     data: <NoteBytes::Object serialized>}
```

The server:
1. Resolves path in alice's ledger → finds `uuid.dat`
2. Reads entire file into buffer
3. Sends the buffer as the `data` field

**Delete:**
```
→ {event: "delete_file", client_id: "alice",
     path: "apps/config/settings"}
← {event: "file_deleted", status: "ok"}
```

**When to use inline:**
- Config files (< 1MB)
- Small NoteBytes objects
- Simple request/response patterns
- Single round-trip, no extra connection needed

---

### Streaming File Operations (Data Channel)

For large files, real-time data, or WebRTC transport.
The data flows over a separate **Channel** (Unix socket, TCP, or WebRTC data channel).

The stream protocol:
1. Client opens a stream on the management socket → gets a `stream_id`
2. Client connects a **device socket** with `stream:<client_id>:<stream_id>` as the device_id
3. Data flows over that socket in 64KB chunks with a 4-byte length prefix

#### Step 1: Open Stream (Management Socket)

```
→ {event: "open_file_stream", client_id: "alice",
     path: "videos/demo.mp4", mode: "write"}
← {event: "stream_opened",
     stream_id: "alice:7f9a8b2c-1d3e-4f5a-6b7c-8d9e0f1a2b3c",
     mode: "write",
     size: 0}
```

The `stream_id` in the response is `"alice:7f9a..."` — it embeds the
client_id so the data channel can verify the client owns the stream.

#### Step 2: Connect Data Channel (Device Socket)

Connect a new socket to the daemon and send a DEVICE_HANDSHAKE:

```
→ {event: "device_handshake",
     device_id: "stream:alice:7f9a8b2c-1d3e-4f5a-6b7c-8d9e0f1a2b3c"}
```

The server:
1. Parses `stream:` prefix, splits into `client_id=alice`, `stream_id=7f9a...`
2. Looks up the stream session
3. Verifies session->client_id matches
4. Routes the socket to the file handle

#### Step 3a: Read Stream (file → client)

```
← [4-byte size][file bytes...]
← (connection closes when transfer completes)
```

The server opens `uuid.dat`, reads 64KB chunks, and writes them directly
to the socket. No buffering — data goes disk → kernel → wire.

#### Step 3b: Write Stream (client → file)

```
→ [4-byte size][file bytes...]
→ (client closes connection when done)
```

The server reads 64KB chunks from the socket and writes them to a temp
file (`uuid.dat.stream`). On client disconnect, it atomically renames
to `uuid.dat`. If a delete raced with the stream, the ledger entry is
re-registered automatically.

**When to use streaming:**
- Large files (videos, datasets, backups)
- Real-time data (logs, telemetry)
- WebRTC transport (browser clients)
- Zero-copy, no server-side buffering

#### Close Stream (optional)

```
→ {event: "close_stream", stream_id: "alice:7f9a..."}
← {event: "stream_closed", status: "ok"}
```

Streams are also cleaned up when the data channel disconnects.

---

### Data Channel Format

Streams use a simple framed format:

```
[4-byte big-endian size][data bytes...]

Example: 1024 bytes of file data
[0x00][0x00][0x04][0x00]  ← size = 1024
[data bytes x1024]          ← the chunk
```

For reads: the server sends one frame with the file size, then the data.
For writes: the client sends one frame. The server writes to a temp file
and renames on completion.

---

### Path Resolution

Each client has a hierarchical **ledger** file at `data/clients/<id>/.ledger`.
The ledger maps path segments to UUID filenames on disk:

```
Ledger structure (NoteBytes::Object):
{
  "apps": {
    "config": {
      "settings": [0x01 → "data/clients/alice/a1b2...dat"]
    },
    "data": [0x01 → "data/clients/alice/c3d4...dat"]
  }
}
```

- `0x01` (FILE_PATH marker) = terminal entry pointing to the actual file
- The ledger is a plain NoteBytes::Object (no encryption)
- Multiple path segments create nested objects (like a filesystem tree)
- `resolve_or_create_path` traverses the hierarchy, creating entries as needed
- This mirrors the Java NotePath system exactly, with encryption stripped
