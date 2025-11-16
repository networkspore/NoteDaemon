NoteDaemon - Secure IO Daemon
---

NoteDaemon provides exclusive access to input devices, bypassing OS-level input systems for secure password entry and other security-critical input scenarios.
Features
```
    -Exclusive Device Access: Detaches kernel drivers to prevent input interception
    -Protocol Negotiation: Multiple modes (RAW, PARSED, ENCRYPTED)
    -End-to-End Encryption: Diffie-Hellman key exchange + AES-256-GCM
    -Secure Buffer Handling: Automatic zeroing of sensitive data
```
Protocol
---
Utilizes Netnotes binary object model
[NoteBytes Wire Protocol Format](protocol_wire_format.md)

Config 
---
Place configfile in your home directory under: ~/.netnotes/config (key=value format)
[config-example](config-example)

Installation
----
Requires daemon and client to be part of the same group, and have adequate priveleges 
to access:
```
/dev/bus/usb/*/*
/dev/hidraw*
```
A recommended setup is to create a udev rule for the USB ports, and create dedicated user 
and group for the application.

Quick Setup:
[Builder bash](build.sh)
[autorun service](note-daemon.service)
[USB rules](99-netnotes.rules)
[configuration bash](setup-netnotes.sh)

Download source and make bash files executable:
```
chmod +x (bash file).sh
```
[Unintall](uninstall-netnotes.sh)