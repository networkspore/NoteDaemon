NoteDaemon - Secure IO Daemon
---

NoteDaemon provides exclusive access to input devices, bypassing OS-level input systems for secure password entry and other security-critical input scenarios.
Features

    -Exclusive Device Access: Detaches kernel drivers to prevent input interception
    -Protocol Negotiation: Multiple modes (RAW, PARSED, ENCRYPTED, FILTERED)
    -End-to-End Encryption: Diffie-Hellman key exchange + AES-256-GCM
    -Privilege Dropping: Runs with minimal privileges after device capture
    -UID Filtering: Optional filtering by user ID
    -Secure Buffer Handling: Automatic zeroing of sensitive data

Config
--
    Path: ~/.netnotes/config
    Format: json or ini