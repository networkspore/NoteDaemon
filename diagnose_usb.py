#!/usr/bin/env python3
"""
USB Device Diagnostic Tool
Enumerates ALL USB devices (bypassing any C++ cache),
performs deep inspection, and checks for Ledger devices.

Usage:
    python3 diagnose_usb.py              # Full scan
    python3 diagnose_usb.py --raw        # Use pyusb raw scan
    python3 diagnose_usb.py --fix-cache  # Clear stale cache entries
"""

import os
import sys
import json
import subprocess
import time
import struct

# ─── Configuration ──────────────────────────────────────────────────────────
DISCOVERY_REGISTRY = os.path.expanduser(
    "~/.netnotes/note_usb/device_registry/discovery.json"
)
CRASH_REGISTRY = "/tmp/netnotes/modules/note_usb/device_registry.json"
SOCKET_PATH = "/run/netnotes/notedaemon.sock"

LEDGER_VID = 0x2C97  # Ledger's vendor ID


def log(msg):
    print(f"[DIAG] {msg}")


# ─── Low-level USB enumeration via sysfs ────────────────────────────────────
def enumerate_usb_via_libusb():
    """Try pyusb first, fall back to lsusb/libusb command"""
    try:
        import usb.core
        import usb.util
        return enumerate_usb_pyusb()
    except ImportError:
        log("pyusb not available, falling back to lsusb")
        return enumerate_usb_lsusb()


def enumerate_usb_pyusb():
    """Enumerate using pyusb (direct libusb access)"""
    import usb.core
    import usb.util

    devices = []
    for dev in usb.core.find(find_all=True):
        try:
            descriptor = {
                "bus": dev.bus,
                "address": dev.address,
                "device_id": f"{dev.bus}:{dev.address}",
                "vid": hex(dev.idVendor),
                "pid": hex(dev.idProduct),
                "manufacturer": usb.util.get_string(dev, dev.iManufacturer) 
                    if dev.iManufacturer else "",
                "product": usb.util.get_string(dev, dev.iProduct) 
                    if dev.iProduct else "",
                "serial": usb.util.get_string(dev, dev.iSerialNumber) 
                    if dev.iSerialNumber else "",
                "bDeviceClass": dev.bDeviceClass,
                "bDeviceSubClass": dev.bDeviceSubClass,
                "bDeviceProtocol": dev.bDeviceProtocol,
                "is_ledger": dev.idVendor == LEDGER_VID,
                "interfaces": [],
            }

            # Get interface descriptors
            if dev.configurations() is not None:
                for cfg in dev.configurations():
                    for iface in cfg.interfaces():
                        if iface.altsettings:
                            alt = iface.altsettings[0]
                            iface_info = {
                                "bInterfaceNumber": alt.bInterfaceNumber,
                                "bInterfaceClass": alt.bInterfaceClass,
                                "bInterfaceSubClass": alt.bInterfaceSubClass,
                                "bInterfaceProtocol": alt.bInterfaceProtocol,
                                "bNumEndpoints": alt.bNumEndpoints,
                                "class_name": usb_class_name(alt.bInterfaceClass),
                                "is_hid": alt.bInterfaceClass == 3,
                            }
                            # Endpoints
                            endpoints = []
                            for ep in alt.endpoints():
                                ep_info = {
                                    "bEndpointAddress": hex(ep.bEndpointAddress),
                                    "bmAttributes": ep.bmAttributes,
                                    "wMaxPacketSize": ep.wMaxPacketSize,
                                }
                                endpoints.append(ep_info)
                            iface_info["endpoints"] = endpoints
                            descriptor["interfaces"].append(iface_info)

            devices.append(descriptor)

        except usb.core.USBError as e:
            log(f"Error accessing device {dev.bus}:{dev.address}: {e}")
        except Exception as e:
            log(f"Unexpected error for device {dev.bus}:{dev.address}: {e}")

    return devices


def enumerate_usb_lsusb():
    """Fallback: use lsusb -v output"""
    devices = []
    
    try:
        result = subprocess.run(
            ["lsusb"], capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
    except Exception as e:
        log(f"lsusb failed: {e}")
        return devices

    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            bus = int(parts[1])
            device = int(parts[3].rstrip(":"))
            vid_pid = parts[5]
            vid, pid = vid_pid.split(":")
            vid = int(vid, 16)
            pid = int(pid, 16)

            descriptor = {
                "bus": bus,
                "address": device,
                "device_id": f"{bus}:{device}",
                "vid": hex(vid),
                "pid": hex(pid),
                "manufacturer": "",
                "product": " ".join(parts[6:]) if len(parts) > 6 else "",
                "serial": "",
                "is_ledger": vid == LEDGER_VID,
                "interfaces": [],
            }

            # Get details with -v
            try:
                detail = subprocess.run(
                    ["lsusb", "-D", f"/dev/bus/usb/{bus:03d}/{device:03d}"],
                    capture_output=True, text=True, timeout=5
                )
                detail_lines = detail.stdout.split("\n")
                
                iManufacturer = ""
                iProduct = ""
                bDeviceClass = 0
                
                for dl in detail_lines:
                    dl = dl.strip()
                    if "iManufacturer" in dl:
                        parts_d = dl.split(maxsplit=1)
                        if len(parts_d) > 1:
                            iManufacturer = parts_d[1]
                    elif "iProduct" in dl:
                        parts_d = dl.split(maxsplit=1)
                        if len(parts_d) > 1:
                            iProduct = parts_d[1]
                    elif "bDeviceClass" in dl:
                        try:
                            bDeviceClass = int(dl.split()[1], 16)
                        except:
                            pass
                
                descriptor["manufacturer"] = iManufacturer if iManufacturer else ""
                descriptor["product"] = iProduct if iProduct else ""
                descriptor["bDeviceClass"] = bDeviceClass
            except:
                pass

            devices.append(descriptor)
        except (ValueError, IndexError) as e:
            log(f"Parse error for line '{line}': {e}")

    return devices


def usb_class_name(cls):
    """Map USB interface class to name"""
    classes = {
        0: "Per-interface",
        1: "Audio",
        2: "Communications",
        3: "HID",
        5: "Physical",
        6: "Image",
        7: "Printer",
        8: "Mass Storage",
        9: "Hub",
        10: "CDC Data",
        11: "Smart Card",
        12: "Content Security",
        13: "Video",
        14: "Video",
        0xDC: "Diagnostic",
        0xE0: "Wireless",
        0xEF: "Miscellaneous",
        0xFE: "Application Specific",
        0xFF: "Vendor Specific",
    }
    return classes.get(cls, f"Unknown(0x{cls:02x})")


# ─── Cache Inspection ──────────────────────────────────────────────────────
def inspect_cache():
    """Inspect the discovery registry cache file"""
    log(f"\n{'='*60}")
    log(f"CACHE INSPECTION")
    log(f"{'='*60}")

    if not os.path.exists(DISCOVERY_REGISTRY):
        log(f"Cache file not found: {DISCOVERY_REGISTRY}")
        return []

    try:
        with open(DISCOVERY_REGISTRY, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        log(f"Cache file is corrupted or not JSON: {e}")
        # Check if it's NoteBytes binary
        with open(DISCOVERY_REGISTRY, "rb") as f:
            header = f.read(8)
        log(f"File header bytes: {header.hex()}")
        return []
    except Exception as e:
        log(f"Error reading cache: {e}")
        return []

    log(f"Cache schema version: {data.get('schema_version', 'unknown')}")
    log(f"Cache last updated: {data.get('updated_at_ms', 'unknown')}")

    devices_data = data.get("devices", {})
    log(f"Total entries in cache: {len(devices_data)}")

    entries = []
    for device_id, dev_data in devices_data.items():
        identity = dev_data.get("identity", {})
        classification = dev_data.get("classification", {})
        status = dev_data.get("status", {})
        
        entry = {
            "device_id": device_id,
            "vid": identity.get("vid", 0),
            "pid": identity.get("pid", 0),
            "scan_level": dev_data.get("scan_level", 0),
            "present": status.get("present", False),
            "device_type": classification.get("device_type", "unknown"),
            "last_seen_ms": dev_data.get("last_seen_ms", 0),
            "detached_at_ms": dev_data.get("detached_at_ms", None),
        }
        entries.append(entry)

        log(f"\n  Entry: {device_id}")
        log(f"    VID:PID = {entry['vid']}:{entry['pid']} (0x{entry['vid']:04x}:0x{entry['pid']:04x})")
        log(f"    scan_level = {entry['scan_level']}")
        log(f"    present = {entry['present']}")
        log(f"    device_type = {entry['device_type']}")
        log(f"    is_ledger = {(int(entry['vid'], 16) if isinstance(entry['vid'], str) else entry['vid']) == LEDGER_VID}")

    return entries


# ─── Cache Fixing ──────────────────────────────────────────────────────────
def fix_cache_stale_entries(live_devices):
    """Remove stale entries from cache that don't correspond to live USB devices"""
    log(f"\n{'='*60}")
    log(f"CACHE CLEANUP")
    log(f"{'='*60}")

    if not os.path.exists(DISCOVERY_REGISTRY):
        log(f"No cache file to fix")
        return

    try:
        with open(DISCOVERY_REGISTRY, "r") as f:
            data = json.load(f)
    except Exception as e:
        log(f"Cannot read cache: {e}")
        return

    devices_data = data.get("devices", {})
    live_ids = {d["device_id"] for d in live_devices}
    stale_ids = [did for did in devices_data.keys() if did not in live_ids]

    if not stale_ids:
        log("No stale cache entries found")
        return

    log(f"Found {len(stale_ids)} stale cache entries:")
    for sid in stale_ids:
        identity = devices_data[sid].get("identity", {})
        vid = identity.get("vid", 0)
        pid = identity.get("pid", 0)
        log(f"  - {sid} (VID:PID=0x{vid:04x}:0x{pid:04x})")

    # Remove stale entries
    for sid in stale_ids:
        del devices_data[sid]

    data["devices"] = devices_data
    data["updated_at_ms"] = int(time.time() * 1000)

    try:
        with open(DISCOVERY_REGISTRY, "w") as f:
            json.dump(data, f, indent=2)
        log(f"✓ Removed {len(stale_ids)} stale entries from cache")
    except Exception as e:
        log(f"✗ Failed to write cache: {e}")


# ─── Crash Registry Inspection ─────────────────────────────────────────────
def inspect_crash_registry():
    """Inspect the crash-recovery registry"""
    log(f"\n{'='*60}")
    log(f"CRASH-RECOVERY REGISTRY")
    log(f"{'='*60}")

    if not os.path.exists(CRASH_REGISTRY):
        log(f"Not found: {CRASH_REGISTRY}")
        return []

    try:
        with open(CRASH_REGISTRY, "r") as f:
            data = json.load(f)
    except Exception as e:
        log(f"Error reading: {e}")
        return []

    log(f"Entries: {len(data) if isinstance(data, list) else 0}")
    for entry in data if isinstance(data, list) else []:
        log(f"  device_id={entry.get('device_id')}, pid={entry.get('pid')}, "
            f"iface={entry.get('interface_number')}, "
            f"kdriver={entry.get('kernel_driver_attached')}")

    return data


# ─── Daemon Connection Test ────────────────────────────────────────────────
def test_daemon_connection():
    """Test if the daemon is accepting connections"""
    log(f"\n{'='*60}")
    log(f"DAEMON CONNECTION TEST")
    log(f"{'='*60}")

    if not os.path.exists(SOCKET_PATH):
        log(f"Socket not found: {SOCKET_PATH}")
        return False

    import socket
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(SOCKET_PATH)
        log(f"✓ Connected to daemon at {SOCKET_PATH}")

        # Send HELLO
        # Build a minimal NoteBytes HELLO message
        # Format: object with EVENT=HELLO
        from io import BytesIO
        
        def write_nb_string(s):
            data = s.encode("utf-8")
            length = len(data).to_bytes(4, 'big')
            return b'\x0b' + length + data  # Type 0x0B = raw bytes for string
            
        def write_nb_int32(val):
            return b'\x03\x00\x00\x00\x04' + struct.pack('>i', val)
            
        def write_nb_pair(key_b, val_b):
            return key_b + val_b
            
        def write_nb_object(pairs):
            result = b''
            for k, v in pairs:
                result += write_nb_pair(k, v)
            length = len(result).to_bytes(4, 'big')
            return b'\x0c' + length + result  # Type 0x0C = object

        hello_msg = write_nb_object([
            (b'\x0b\x00\x00\x00\x05event', b'\x0b\x00\x00\x00\x05HELLO'),
            (b'\x0b\x00\x00\x00\x06status', b'\x0b\x00\x00\x00\x06client'),
        ])
        
        sock.sendall(hello_msg)
        sock.settimeout(5)
        
        try:
            resp = sock.recv(4096)
            log(f"✓ Got response ({len(resp)} bytes)")
        except socket.timeout:
            log(f"⚠ Response timeout (may need proper NoteBytes handshake)")
        
        sock.close()
        return True
    except Exception as e:
        log(f"✗ Connection failed: {e}")
        return False


# ─── Ledger-Specific Check ────────────────────────────────────────────────
def check_ledger(devices):
    """Check if any Ledger devices are present"""
    log(f"\n{'='*60}")
    log(f"LEDGER DEVICE CHECK")
    log(f"{'='*60}")

    ledger_devices = [d for d in devices if d.get("is_ledger") or 
                      (isinstance(d.get("vid"), str) and int(d["vid"], 16) == LEDGER_VID) or
                      (isinstance(d.get("vid"), int) and d["vid"] == LEDGER_VID)]

    if ledger_devices:
        log(f"✓ Found {len(ledger_devices)} Ledger device(s)!")
        for ld in ledger_devices:
            log(f"\n  Device: {ld.get('device_id')}")
            log(f"    VID:PID = {ld.get('vid')}:{ld.get('pid')}")
            log(f"    Product: {ld.get('product', 'N/A')}")
            log(f"    Manufacturer: {ld.get('manufacturer', 'N/A')}")
            log(f"    Serial: {ld.get('serial', 'N/A')}")
            if "interfaces" in ld:
                for iface in ld["interfaces"]:
                    log(f"    Interface {iface.get('bInterfaceNumber')}: "
                        f"class={iface.get('bInterfaceClass')} "
                        f"({iface.get('class_name')})")
    else:
        log(f"✗ No Ledger device found!")
        log(f"  Make sure:")
        log(f"  1. Ledger is plugged in via USB")
        log(f"  2. Ledger is unlocked")
        log(f"  3. You're on the home screen or an app")
        log(f"  4. Check dmesg for USB detection issues")

    return len(ledger_devices) > 0


# ─── Main Diagnostic ──────────────────────────────────────────────────────
def main():
    print(f"""
{'='*60}
 USB DEVICE DIAGNOSTIC TOOL
 Enumerates all USB devices, checks caches, detects Ledger
{'='*60}
""")

    fix_cache = "--fix-cache" in sys.argv

    # Step 1: Enumerate all USB devices via libusb/libusb
    log("Step 1: Enumerating all USB devices...")
    devices = enumerate_usb_via_libusb()
    log(f"Found {len(devices)} USB device(s)\n")

    # Print live device table
    log(f"{'─'*60}")
    log(f"LIVE USB DEVICES")
    log(f"{'─'*60}")
    log(f"{'ID':>8} {'VID:PID':>14} {'Type':>16} {'Product':>30}")
    log(f"{'─'*60}")
    for d in devices:
        device_id = d.get("device_id", "?")
        vid = d.get("vid", "?")
        pid = d.get("pid", "?")
        product = d.get("product", "")[:30]
        
        # Get device type
        dtype = "unknown"
        if d.get("is_ledger") or str(vid) == hex(LEDGER_VID):
            dtype = "LEDGER!"
        else:
            for iface in d.get("interfaces", []):
                if iface.get("is_hid"):
                    dtype = "HID"
                    break
        
        log(f"{device_id:>8} {str(vid)+':'+str(pid):>14} {dtype:>16} {product:>30}")

    # Step 2: Inspect cache
    log(f"\nStep 2: Inspecting discovery cache...")
    cache_entries = inspect_cache()

    # Step 3: Check Ledger
    log(f"\nStep 3: Checking for Ledger devices...")
    has_ledger = check_ledger(devices)

    # Step 4: Inspect crash registry
    log(f"\nStep 4: Checking crash-recovery registry...")
    inspect_crash_registry()

    # Step 5: Test daemon connection
    log(f"\nStep 5: Testing daemon connectivity...")
    test_daemon_connection()

    # Step 6: Fix cache if requested
    if fix_cache:
        log(f"\nStep 6: Fixing stale cache entries...")
        fix_cache_stale_entries(devices)

    # Summary
    log(f"\n{'='*60}")
    log(f"SUMMARY")
    log(f"{'='*60}")
    log(f"USB devices found: {len(devices)}")
    log(f"Ledger detected: {'YES ✓' if has_ledger else 'NO ✗'}")
    log(f"Cache entries: {len(cache_entries)}")
    log(f"\nIf no Ledger device is listed above, it is NOT connected/visible to USB.")
    log(f"Check physical connection, try different USB port, or check dmesg.")
    log(f"\nTo fix stale cache: {sys.argv[0]} --fix-cache")


if __name__ == "__main__":
    main()
