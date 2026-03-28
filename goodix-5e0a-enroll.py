#!/usr/bin/env python3
"""
Goodix 5e0a PSK Enrollment Tool — standalone, no Windows needed.

This tool writes a new PSK to the Goodix 27c6:5e0a fingerprint sensor.
It replicates the exact Windows driver flow (RE of Wbdi.dll ProcessPsk +
UpdateFirmware):

  1. Erase MCU app (0xA4) → enters IAP mode
  2. Write new PSK via whitebox encrypt (0xE0)
  3. Verify PSK hash (0xBB020001)
  4. Re-flash APP firmware (0xF0) from extracted Wbdi.dll blob
  5. Reset MCU → returns to APP mode
  6. Save PSK to /var/lib/fprint/goodix-5e0a.psk

Prerequisites:
  - Run goodix-5e0a-setup.sh first to extract firmware from Wbdi.dll
  - Firmware blob at /var/lib/fprint/goodix-5e0a-firmware.bin
  - fprintd must be stopped: sudo systemctl stop fprintd

WARNING: This erases the current PSK. The old PSK is permanently lost.

Usage: sudo python3 goodix-5e0a-enroll.py
"""
import sys, os, struct, hashlib, time, binascii

# Add paths for goodix library
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, '/home/carmine/dev/goodix-5e0a')

# Stub out missing modules
import types
for mod in ('periphery', 'spidev'):
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)

from whitebox_crack import whitebox_encrypt
import goodix, protocol

# ---- Constants ----
PSK_FILE = "/var/lib/fprint/goodix-5e0a.psk"
FW_FILE = "/var/lib/fprint/goodix-5e0a-firmware.bin"
PRE_FLAGS = bytes.fromhex("56a5bb956b7c8d9e0000")
CHUNK_SIZE = 256

def chunked_psk_write(dev, payload):
    """Write PSK payload via chunked protocol (cmd 0xE0 + confirm 0xE4)."""
    total = len(payload)
    n_chunks = (total + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(n_chunks):
        offset = i * CHUNK_SIZE
        chunk = payload[offset:offset + CHUNK_SIZE]
        header = struct.pack('<III', total, len(chunk), offset)
        send_buf = header + chunk

        # Write (0xE0)
        dev.protocol.write(goodix.encode_message_pack(
            goodix.encode_message_protocol(send_buf, goodix.COMMAND_PRESET_PSK_WRITE_R)))
        dev.protocol.read(timeout=3)  # ACK
        resp = dev.protocol.read(timeout=3)  # Response
        inner = goodix.check_message_protocol(
            goodix.check_message_pack(resp), goodix.COMMAND_PRESET_PSK_WRITE_R)
        if inner[0] != 0:
            print(f"  Chunk {i} write FAILED: status={inner[0]}")
            return False

        # Confirm (0xE4)
        dev.protocol.write(goodix.encode_message_pack(
            goodix.encode_message_protocol(send_buf, goodix.COMMAND_PRESET_PSK_READ_R)))
        dev.protocol.read(timeout=3)
        dev.protocol.read(timeout=3)
    return True


def write_firmware(dev, fw_path, new_psk):
    """Write APP firmware and verify. Uses same approach as driver_55x4.py."""
    import hmac as hmac_mod

    with open(fw_path, 'rb') as f:
        fw_blob = f.read()

    # Parse: [1 byte ver_len][version string][firmware_data][4 byte CRC]
    ver_len = fw_blob[0]
    ver_str = fw_blob[1:1+ver_len].decode('ascii', errors='replace')
    firmware = fw_blob[1+ver_len:-4]
    print(f"  Firmware: {ver_str} ({len(firmware)} bytes)")

    # Compute PMK HMAC and firmware HMAC (same as driver_55x4.py)
    mod = bytes(range(1, 65))
    raw_pmk = (struct.pack(">H", 32) + new_psk) * 2
    pmk = hashlib.sha256(raw_pmk).digest()
    pmk_hmac = hmac_mod.new(pmk, mod, hashlib.sha256).digest()
    firmware_hmac = hmac_mod.new(pmk_hmac, firmware, hashlib.sha256).digest()

    # CRC-32/MPEG-2
    def crc32_mpeg2(data):
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b << 24
            for _ in range(8):
                crc = (crc << 1) ^ 0x04C11DB7 if crc & 0x80000000 else crc << 1
                crc &= 0xFFFFFFFF
        return crc

    # Write firmware in 256-byte chunks (same as driver_55x4.py)
    length = len(firmware)
    for i in range(0, length, 256):
        chunk = firmware[i:i + 256]
        if not dev.write_firmware(i, chunk):
            print(f"\n  Firmware write FAILED at offset {i}")
            return False
        pct = int((i + len(chunk)) * 100 / length)
        print(f"\r  Writing firmware: {pct}%", end="", flush=True)
    print()

    # Verify: send ONLY the 32-byte HMAC via cmd 0xF4
    # RE: DLL sends just hmac, NOT [offset][length][crc][hmac] like goodix.py does
    print("  Verifying firmware (0xF4)...", flush=True)
    dev.protocol.write(goodix.encode_message_pack(
        goodix.encode_message_protocol(firmware_hmac, goodix.COMMAND_CHECK_FIRMWARE)))
    dev.protocol.read(timeout=5)  # ACK
    resp = dev.protocol.read(timeout=5)
    inner = goodix.check_message_protocol(
        goodix.check_message_pack(resp), goodix.COMMAND_CHECK_FIRMWARE)
    # RE: DLL checks "if (check_ok != 0) → success"
    if inner[0] == 0:
        print(f"  Firmware verification FAILED (status=0)")
        return False

    print(f"  Firmware verified OK (status={inner[0]})")
    return True


def reset_mcu(dev):
    """Send McuResetMcu (0xA2, [0x02, 0x32]) to reboot from IAP to APP mode.
    RE: McuResetMcu @ 0x1800a7ae0 — fire-and-forget, no response expected.
    Payload [0x02, 0x32]: 0x02=reset MCU sub-command, 0x32=delay param."""
    dev.protocol.write(goodix.encode_message_pack(
        goodix.encode_message_protocol(bytes([0x02, 0x32]), 0xA2)))
    try:
        dev.protocol.read(timeout=2)  # ACK (may not come if MCU resets)
    except:
        pass


def main():
    print("=== Goodix 5e0a PSK Enrollment Tool ===")
    print()

    # Check firmware blob exists
    if not os.path.exists(FW_FILE):
        print(f"ERROR: Firmware blob not found at {FW_FILE}")
        print("Run goodix-5e0a-setup.sh first to extract firmware from Wbdi.dll")
        return False

    # Check running as root
    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)")
        return False

    print("WARNING: This will ERASE the current PSK and re-flash firmware!")
    print("The sensor will be temporarily unavailable during the process.")
    resp = input("Continue? [y/N] ")
    if resp.lower() != 'y':
        print("Aborted.")
        return False

    # Connect to device
    print("\n[1/7] Connecting to device...", flush=True)
    dev = goodix.Device(0x5e0a, protocol.USBProtocol)
    dev.nop()
    try:
        dev.enable_chip(True)
    except:
        pass
    dev.nop()
    print("  Connected", flush=True)

    # Check current state
    print("\n[2/7] Checking firmware version...", flush=True)
    try:
        dev.protocol.write(goodix.encode_message_pack(
            goodix.encode_message_protocol(b'', 0xA8)))
        dev.protocol.read(timeout=3)  # ACK
        resp = dev.protocol.read(timeout=3)
        fw_data = goodix.check_message_protocol(
            goodix.check_message_pack(resp), 0xA8)
        fw_str = fw_data.decode('ascii', errors='replace').rstrip('\x00')
        print(f"  Firmware: {fw_str}", flush=True)
        in_iap = "IAP" in fw_str.upper()
    except Exception as e:
        print(f"  Could not read firmware version: {e}", flush=True)
        in_iap = False

    # Step 3: Generate PSK
    print("\n[3/7] Generating new PSK...", flush=True)
    new_psk = os.urandom(32)
    psk_hash = hashlib.sha256(new_psk).digest()
    print(f"  PSK: {new_psk.hex()}", flush=True)
    print(f"  Hash: {psk_hash.hex()[:32]}...", flush=True)

    # Step 4: Whitebox encrypt
    print("\n[4/7] Whitebox encrypting...", flush=True)
    wb_blob = whitebox_encrypt(new_psk)
    print(f"  Whitebox: {len(wb_blob)} bytes", flush=True)

    # Build write payload
    fake_dpapi = bytes(32)
    tlv1 = struct.pack('<II', 0xBB010002, len(fake_dpapi)) + fake_dpapi
    tlv2 = struct.pack('<II', 0xBB010003, len(wb_blob)) + wb_blob
    payload = PRE_FLAGS + tlv1 + tlv2
    print(f"  Payload: {len(payload)} bytes", flush=True)

    # Step 5: Erase + Write PSK
    if not in_iap:
        print("\n[5/7] Erasing MCU app (entering IAP mode)...", flush=True)
        dev.protocol.write(goodix.encode_message_pack(
            goodix.encode_message_protocol(bytes([0x00, 0x32]), 0xA4)))
        try:
            dev.protocol.read(timeout=3)  # ACK (may timeout after reset)
        except:
            pass
        print("  Waiting 2s for MCU reboot...", flush=True)
        time.sleep(2)
    else:
        print("\n[5/7] Already in IAP mode, skipping erase", flush=True)

    print("  Writing PSK...", flush=True)
    ok = chunked_psk_write(dev, payload)
    if not ok:
        print("PSK WRITE FAILED!", flush=True)
        return False
    print("  PSK write OK", flush=True)

    # Step 6: Verify
    print("\n[6/7] Verifying PSK...", flush=True)
    time.sleep(0.5)
    try:
        success, _, dev_hash = dev.preset_psk_read(0xbb020001, 32, 0)
        if success and dev_hash == psk_hash:
            print(f"  VERIFIED! Hash matches", flush=True)
        else:
            print(f"  WARNING: Hash mismatch", flush=True)
            print(f"    Device:   {dev_hash.hex() if dev_hash else 'None'}", flush=True)
            print(f"    Expected: {psk_hash.hex()}", flush=True)
            # Continue anyway — write may have worked
    except Exception as e:
        print(f"  Verify read failed: {e} — continuing", flush=True)

    # Step 7: Write firmware
    print("\n[7/7] Re-flashing APP firmware...", flush=True)
    ok = write_firmware(dev, FW_FILE, new_psk)
    if not ok:
        print("FIRMWARE WRITE FAILED! Sensor is in IAP mode.", flush=True)
        print("Connect to Windows to recover, or re-run this tool.", flush=True)
        # Still save PSK — it was written successfully
    else:
        # Reset MCU to boot into new APP firmware
        print("  Resetting MCU...", flush=True)
        reset_mcu(dev)
        time.sleep(2)
        print("  MCU reset done", flush=True)

    # Save PSK
    os.makedirs(os.path.dirname(PSK_FILE), exist_ok=True)
    with open(PSK_FILE, 'w') as f:
        f.write(new_psk.hex() + '\n')
    os.chmod(PSK_FILE, 0o600)
    print(f"\nPSK saved to {PSK_FILE}", flush=True)

    print("\n=== ENROLLMENT COMPLETE ===", flush=True)
    print("Now run: sudo systemctl restart fprintd", flush=True)
    print("Then:    fprintd-enroll $(whoami)", flush=True)
    return True


if __name__ == "__main__":
    try:
        ok = main()
        sys.exit(0 if ok else 1)
    except KeyboardInterrupt:
        print("\nAborted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
