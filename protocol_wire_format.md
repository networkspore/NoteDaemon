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
