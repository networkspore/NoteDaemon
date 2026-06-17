# Phase 2 – Next Steps (Post-Claim/Discovery Hardening)

This document tracks deferred/next-phase work for the discovery, claim, and device ownership system.
These items are not required for correctness today, but are important for robustness, persistence,
and edge-case safety.

Scope note:
- NoteUSB discovery/claim/persistent-registry implementation lives in the external module project
  at `../NoteUSB`, not in NoteDaemon core.
- NoteDaemon core remains module-agnostic and only provides module lifecycle, routing, and shared
  interfaces.

Items are marked with:
- Priority: High / Medium / Low
- Rationale: short reasoning
- Notes: implementation hints

---

## R1: Persistent Device Registry (High)

Goal:
- Survive daemon and client restarts with known device metadata and ownership hints.
- Avoid re-discovering everything from scratch; allow warm boot.

Design:
- Storage:
  - Use JSON (simple, human-readable, no extra dependencies).
  - One file: e.g., `device_registry.json` (configurable via env or daemon config).
  - Disk-backed only: do not keep a long-lived in-memory mirror/cache of the persistent registry.
    Read from disk when needed and write updates back atomically.
- What to store:
  - Static device characteristics:
    - device_id
    - vid, pid
    - serial (if present)
    - product_name / manufacturer (if known)
    - first_seen, last_seen
    - stable capability hints (e.g., known module_id, known modes)
  - Ownership hints (non-authoritative):
    - last_claiming_pid
    - last_claiming_session_id
    - last_claim_time
  - Do NOT store volatile runtime state (e.g., current USB handle, in-flight locks).
- Update policy:
  - On DEVICE_ATTACHED / discovery:
    - Insert or update static fields.
    - Update last_seen.
  - On claim:
    - Update ownership hints.
  - On DEVICE_DETACHED:
    - Mark detached_at; do not delete entry.
- Staleness model:
  - Static fields are effectively non-stale (VID/PID, product name).
  - Ownership hints are stale quickly; treat as suggestion only.
  - Add:
    - `stale_after_ms` per field category:
      - Ownership: e.g., 60_000 ms
      - Capability hints: e.g., 1_800_000 ms (30 minutes)
  - Consumers should:
    - Trust static fields.
    - Treat stale ownership hints as "likely", not "definitive."

Implementation notes:
- Add:
  - Module-side persistent registry implementation in `../NoteUSB` (discovery registry backend).
  - Registry materialization on module init, with disk-backed read/modify/write per operation.
  - JSON write on:
    - attach
    - claim
    - detach
    - periodic flush (e.g., every 60 seconds)
- Keep the in-memory DeviceOwnershipRegistry as the single source of truth for live claims.
- Persistent registry is only for hints and durable metadata.
- Access pattern:
  - Persistent registry API should be stateless and file-backed (read/modify/write per operation).
  - Use file locking and atomic replace (write temp + rename) to avoid corruption.

---

## R2: Staleness and "safe to store" rules (High)

Rule:
- If information can go stale and affect correctness, it must:
  - Either: be explicitly versioned/timestamped with a defined stale_after_ms,
  - Or: not be stored persistently at all.

Categories:
- Safe to store (non-stale):
  - VID/PID
  - Device identity
  - Product name / manufacturer
  - Known static capabilities (e.g., "supports parsed mode")
- Conditional (stale):
  - last_claiming_pid/session
  - last_used_module
  - last_seen
  - Must include:
    - timestamp
    - stale_after_ms
- Not suitable for persistent storage:
  - In-flight locks
  - Short-lived USB handles
  - Transient error states

Any future persistent registry changes must follow these rules.

---

## R3: sysfs fallback for check_kernel_driver_active() (Medium)

Rationale:
- We have seen "device or resource busy" errors when using libusb_open(),
  even when the device is logically available.
- In some environments (or with some udev rules), libusb_open() may fail
  temporarily or be restricted (e.g., permissions, concurrent access).
- Using sysfs as a fallback:
  - Avoids opening the device just to probe.
  - Reduces interference with kernel drivers and other processes.

Design:
- Primary:
  - Use existing libusb-based check_kernel_driver_active().
- Fallback (if libusb_open() fails with LIBUSB_ERROR_BUSY or LIBUSB_ERROR_ACCESS):
  - Read:
    - /sys/bus/usb/devices/<bus>-<port>//interface/<interface>/driver
  - If:
    - Directory exists and "driver" symlink is present → kernel driver active.
    - Directory missing or no driver → treat as not kernel-held.
- Behavior:
  - If primary fails and fallback indicates kernel driver active:
    - Treat as kernel-held (safe).
  - If fallback indicates no kernel driver:
    - Still treat as kernel-held to avoid false negatives.
    - Log a warning that we used a conservative decision.

Implementation notes:
- Implement as:
  - bool check_kernel_driver_via_sysfs(device_path)
- Only enable if:
  - libusb_open() fails with LIBUSB_ERROR_BUSY or LIBUSB_ERROR_ACCESS, or
  - An environment flag is set (e.g., NETNOTES_USE_SYSFS_FALLBACK=1).

---

## R4: Enhanced test coverage for PID/session and kernel checks (Medium)

Rationale:
- The claim and ownership system is now central; incorrect behavior can
  silently break multi-client safety.

Tests to add:
- Unit tests:
  - DeviceOwnershipRegistry:
    - register_device(device_id, module_id, pid, session_id)
    - is_claimed(device_id)
    - is_claimed_by_pid(device_id, pid)
    - get_owner(device_id)
  - claim_device():
    - Same-PID re-claim: allowed
    - Different-PID claim: PID_MISMATCH
  - check_kernel_driver_active():
    - libusb_open failure → kernel-held
    - kernel driver on interface 1 → kernel-held
    - no kernel driver → not kernel-held

Notes:
- If mocking libusb is hard, we can:
  - Use a small wrapper interface for libusb calls and mock in tests.
  - Or add integration tests that run against a real daemon with controlled udev rules.

---

## R5: Unified handling of "busy" errors in discovery (Low)

Rationale:
- "Device or resource busy" errors during libusb_open() can cause false negatives.
- We should:
  - Log them clearly.
  - Optionally retry once.
  - Fall back to sysfs-based check (see R3).

This can be implemented once we see patterns in production logs.

---

## R6: Optional – persistent registry consumer in Java (Low)

Rationale:
- Java client could use the persistent registry for:
  - Faster startup (pre-populate known devices).
  - Better UX (show "Known device" vs "New device").

Constraints:
- Must not bypass daemon's live ownership rules.
- Must respect staleness rules (R2).

This is a "nice to have" and should be considered only after R1/R2 are stable.

---

## NoteFile Service Items

### Phase 1 (Done)
- [x] NoteFileHandle – streamable NoteBytes with per-client zone ID
- [x] NoteFileService – auth provider + file CRUD + zone isolation
- [x] Plaintext ledger (Java NotePath port, encryption stripped)
- [x] Admin API key authentication (SHA-256 hashed)
- [x] Client API key authentication + per-client zones
- [x] Management handlers: admin_auth, add/remove/list clients, get/put/delete file
- [x] 10 unit tests passing

### Phase 2 (Next)
- [ ] TLS integration – server.key for SSL transport
- [ ] Data channel streaming – NoteFile read/write over WebRTC/TCP/Unix Channel
- [ ] Client password change – re-encrypt zone data with new key
- [ ] Zone quota enforcement – disk space limits per client_id
- [ ] Admin API key rotation – replace key without downtime
- [ ] Audit logging – track file access per client_id
- [ ] Garbage collection – clean up orphaned .dat files after ledger changes
