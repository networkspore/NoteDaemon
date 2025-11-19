NoteDaemon - Secure IO Daemon - (currently Linux only)
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

A recommended setup is to create a udev rule for the USB ports, and create dedicated user 
and group for the application.

QuickInstall:
```
#if you need curl:
sudo apt update
sudo apt install curl

#get install script
curl -fsSL https://raw.githubusercontent.com/networkspore/NoteDaemon/master/download-install.sh -o 

install.sh
less install.sh  # Review the script
sudo bash install.sh
```

Scripts: 

[Download install](download-install.sh) 

[Builder bash](build.sh)  

[configuration bash](setup-netnotes.sh) 

[Unintall](uninstall-netnotes.sh) 


Download source and make bash files executable:
```
chmod +x (bash file).sh
```

Requires daemon and client to be part of the netnotes group, and have adequate priveleges 
to access the socket and USB device - see [rules](99-netnotes.rules)
```
/dev/bus/usb/*/* #owned by root, cannot limit access
/dev/hidraw* #limit access
```
