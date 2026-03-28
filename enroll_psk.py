#!/usr/bin/env python3
"""
Enroll a new PSK on the Goodix 5e0a sensor from Linux. No Windows needed.

WARNING: This ERASES the current PSK. The old PSK is permanently lost.
The new PSK is saved to /etc/libfprint/goodix-5e0a.psk.

Flow: erase_app → sleep → generate PSK → whitebox encrypt → write → verify → save
"""
import sys, types, os, struct, hashlib, time
sys.path.insert(0, '/home/carmine/dev/goodix-5e0a')
sys.modules['periphery'] = types.ModuleType('periphery')
sys.modules['spidev'] = types.ModuleType('spidev')

sys.path.insert(0, '/home/carmine/dev/libfprint-goodix')
from whitebox_crack import whitebox_encrypt

import goodix, protocol

PRE_FLAGS = bytes.fromhex("56a5bb956b7c8d9e0000")
PSK_FILE = "/etc/libfprint/goodix-5e0a.psk"
CHUNK_SIZE = 256

def chunked_write(dev, payload):
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
        inner = goodix.check_message_protocol(goodix.check_message_pack(resp), goodix.COMMAND_PRESET_PSK_WRITE_R)
        if inner[0] != 0:
            print(f"  Chunk {i} write FAILED: {inner.hex()}")
            return False
        # Confirm (0xE4)
        dev.protocol.write(goodix.encode_message_pack(
            goodix.encode_message_protocol(send_buf, goodix.COMMAND_PRESET_PSK_READ_R)))
        dev.protocol.read(timeout=3)
        dev.protocol.read(timeout=3)
    return True

def main():
    print("=== Goodix 5e0a PSK Enrollment ===", flush=True)
    print("WARNING: This will ERASE the current PSK!", flush=True)
    print()

    dev = goodix.Device(0x5e0a, protocol.USBProtocol)
    dev.nop()
    try: dev.enable_chip(True)
    except: pass
    dev.nop()

    # Step 1: Generate PSK
    new_psk = os.urandom(32)
    psk_hash = hashlib.sha256(new_psk).digest()
    print(f"New PSK: {new_psk.hex()}", flush=True)
    print(f"Hash:    {psk_hash.hex()}", flush=True)

    # Step 2: Whitebox encrypt
    wb_blob = whitebox_encrypt(new_psk)
    print(f"Whitebox: {len(wb_blob)}B", flush=True)

    # Step 3: Build write payload
    # TLV1: fake DPAPI (MCU stores opaquely)
    fake_dpapi = bytes(32)
    tlv1 = struct.pack('<II', 0xBB010002, len(fake_dpapi)) + fake_dpapi
    # TLV2: whitebox (MCU decrypts to get PSK)
    tlv2 = struct.pack('<II', 0xBB010003, len(wb_blob)) + wb_blob
    payload = PRE_FLAGS + tlv1 + tlv2
    print(f"Payload: {len(payload)}B", flush=True)

    # Step 4: Erase app
    print("\nErasing MCU app (entering IAP mode)...", flush=True)
    dev.protocol.write(goodix.encode_message_pack(
        goodix.encode_message_protocol(bytes([0x00, 0x32]), 0xA4)))
    try:
        dev.protocol.read(timeout=3)  # ACK (may timeout)
    except:
        pass

    print("Sleeping 2s for MCU reboot...", flush=True)
    time.sleep(2)

    # Step 5: Write
    print("Writing PSK...", flush=True)
    ok = chunked_write(dev, payload)
    if not ok:
        print("WRITE FAILED!", flush=True)
        return False
    print("Write OK", flush=True)

    # Step 6: Verify
    print("Verifying...", flush=True)
    time.sleep(1)
    success, _, dev_hash = dev.preset_psk_read(0xbb020001, 32, 0)
    if success and dev_hash == psk_hash:
        print(f"VERIFIED! Hash matches: {dev_hash.hex()}", flush=True)
    else:
        print(f"VERIFY FAILED!", flush=True)
        print(f"  Device: {dev_hash.hex() if dev_hash else 'None'}", flush=True)
        print(f"  Expected: {psk_hash.hex()}", flush=True)
        # Save anyway — the write may have worked

    # Step 7: Save PSK
    os.makedirs(os.path.dirname(PSK_FILE), exist_ok=True)
    with open(PSK_FILE, 'w') as f:
        f.write(new_psk.hex() + '\n')
    os.chmod(PSK_FILE, 0o600)
    print(f"\nPSK saved to {PSK_FILE}", flush=True)
    print("DONE!", flush=True)
    return True

if __name__ == "__main__":
    main()
