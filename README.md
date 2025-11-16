NoteDaemon - Secure IO Daemon
---

NoteDaemon provides exclusive access to input devices, bypassing OS-level input systems for secure password entry and other security-critical input scenarios.
Features

    -Exclusive Device Access: Detaches kernel drivers to prevent input interception
    -Protocol Negotiation: Multiple modes (RAW, PARSED, ENCRYPTED)
    -End-to-End Encryption: Diffie-Hellman key exchange + AES-256-GCM
    -Secure Buffer Handling: Automatic zeroing of sensitive data

Protocol
---
Utilizes Netnotes binary object model
See: NoteBytes Wire Protocol Format

Config 
---
Location: ~/.netnotes/config (key=value format)
See: config-example

Installation
----
See: setup-netnotes.sh

Uninstall
see: uninstall-netnotes.sh