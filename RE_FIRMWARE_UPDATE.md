# Reverse Engineering: Firmware Update & WriteApp Flow

Source: `Wbdi.dll` from Goodix FingerPrint V3.0.141.150_21H1_signed
Functions: UpdateFirmware (0x18009ae10), WriteApp (0x18009f6a8), _WriteFw (0x18009ff90)
Tool: radare2 disassembly of x86-64 PE

---

## 1. UpdateFirmware (0x18009ae10) — The Master Orchestrator

Source file: `d:\project\master\winfpcode2\driver\wbdi\mcu\geneva\updatefirmware.c`

This function is called during device loading (Phase 1) and handles ALL firmware management:
PSK enrollment, firmware version checking, firmware writing, and MCU mode transitions.

### Flow Overview

```
UpdateFirmware(ctx, arg2):
  1. GetFirmwareVersion(ctx) → parse version string
  2. Determine mode from version: "APP", "IAP", "TESTAPP", "TESTIAP", "FARFRRAPP"

  APP mode path:
    a. If forceFirmwareUpdate flag → erase APP → ProcessPsk → recursive UpdateFirmware
    b. CompareVersion(embedded_fw, device_fw):
       - Returns 0: "do not upgrade" → done (SUCCESS)
       - Returns 1: "firmware version not equal" → erase APP → ProcessPsk → recursive UpdateFirmware
       - Returns 4/5: error

  IAP mode path:
    a. UpdateInIap(version_struct):
       - Returns 2: "IAP is equal, write APP" → WriteApp → Sleep(1000) → ProcessPsk → McuSetDrvState → restart
       - Returns 3: "IAP is not equal" → WriteIap → restart
       - Returns 4: error

  TESTAPP/FARFRRAPP path:
    → erase APP → ProcessPsk → recursive UpdateFirmware
```

### Critical Insight: The Recursive Loop

After erase_app + ProcessPsk, UpdateFirmware calls itself recursively:
1. First call (APP mode): erase → ProcessPsk (writes PSK in IAP) → recurse
2. Second call (IAP mode): detects IAP → WriteApp (writes firmware) → McuResetMcu → restart
3. Third call (APP mode): CompareVersion = 0 → "do not upgrade" → SUCCESS

The MCU transitions: APP → (erase) → IAP → (WriteApp) → APP

### Call Sites for ProcessPsk within UpdateFirmware

| Address | Mode | Context | After ProcessPsk |
|---------|------|---------|------------------|
| 0x18009b25e | APP | forceFirmwareUpdate=TRUE | Recursive UpdateFirmware |
| 0x18009b4b2 | APP | Version mismatch | Recursive UpdateFirmware |
| 0x18009b662 | IAP | After WriteApp success | McuSetDrvState → restart loop |
| 0x18009b9d0 | TEST | TESTAPP/FARFRRAPP | Recursive UpdateFirmware |

---

## 2. WriteApp (0x18009f6a8) — Firmware Write Function

### Pseudo-code

```c
int WriteApp(void *ctx) {
    // Step 1: Get embedded firmware from global
    FirmwareBlob *fw = g_app_firmware;  // [0x180246848]
    // fw->data = 0x180188fd0, fw->size = 0x65C1 (26049 bytes)
    // Version: "GFUSB_GM168SEC_APP_10034"

    // Step 2: CRC check embedded firmware
    if (!check_crc(fw->data, fw->size)) {
        LOG("check app crc failed, do not update");
        return 0;
    }

    // Step 3: Parse firmware header, prepare write buffer
    int ver_len = fw->data[0] + 1;          // skip version string
    int payload_size = fw->size - ver_len - 4;  // subtract header + trailing CRC
    int buf_size = payload_size + 12;        // 12-byte header + payload

    BYTE *buf = malloc(buf_size);
    DWORD *hdr = (DWORD*)buf;
    hdr[1] = payload_size;                   // firmware size
    hdr[2] = crc32(fw->data + ver_len, payload_size);  // CRC of firmware
    hdr[0] = crc32(&hdr[1], 8);             // CRC of header
    memcpy(&hdr[3], fw->data + ver_len, payload_size);

    // Step 4: Write firmware via cmd 0xF0 (chunked, 256B per chunk)
    if (!_WriteFw(ctx, buf, buf_size, 2/*=APP*/)) {
        LOG("failed"); goto cleanup;
    }

    // Step 5: Get PMK HMAC from MCU
    LOG("check firmware...");
    production_get_pmk_hmac(ctx, &pmk_hmac);  // reads from device

    // Step 6: Compute HMAC-SHA256(pmk_hmac, written_data)
    SecHmacSha256(pmk_hmac, 32, buf, buf_size, &hmac);

    // Step 7: Send verification HMAC to MCU via cmd 0xF4
    mcu_send_cmd(ctx, 0xF4, hmac, 32, ...);

    // Step 8: Check result and reset MCU
    if (check_ok) {
        LOG("check firmware suc");
        LOG("update app suc, reset mcu...");
        McuResetMcu(ctx, 0);     // RESET MCU → boots into new APP firmware
        return 1;
    }

cleanup:
    free(buf);
    return 0;
}
```

### MCU Commands Used

| Command | Hex | Function | Data |
|---------|-----|----------|------|
| **0xF0** | Write Firmware | Chunked, 256B/chunk | `[offset:4][length:4][mode:4][payload:N]` |
| **0xF4** | Verify Firmware | HMAC-SHA256 check | `[hmac:32]` |
| **McuResetMcu** | Reset to APP | After successful verify | Via fcn.1800a7ae0 |

### _WriteFw (0x18009ff90) — Chunked Write Loop

```c
int _WriteFw(void *ctx, BYTE *data, DWORD total_size, int mode) {
    // mode: 0=IAP, 2=APP
    DWORD chunk_size = 256;

    while (bytes_left > 0) {
        DWORD offset = total_size - bytes_left;
        DWORD this_chunk = min(chunk_size, bytes_left);

        // Packet: [offset:4][chunk_len:4][mode:4][data:chunk_len]
        // Send via MCU command 0xF0
        mcu_send_cmd(ctx, 0xF0, packet, this_chunk + 12, ...);

        bytes_left -= this_chunk;
        LOG("total: 0x%x, bytes left: 0x%x", total_size, bytes_left);
    }
    return 1;
}
```

---

## 3. Embedded Firmware Data

The firmware binaries are embedded in the DLL's `.rdata` section:

| Type | Address | Size | Version String |
|------|---------|------|----------------|
| APP firmware | 0x180188fd0 | 0x65C1 (26049B) | `GFUSB_GM168SEC_APP_10034` |
| IAP firmware 1 | 0x1801a4a20 | 0x5691 (22161B) | `MILAN_GM168SEC_IAP_100071` |
| IAP firmware 2 | 0x1801aa0c0 | 0x4011 (16401B) | `MILAN_GM168SEC_IAP_200031` |

### Firmware Blob Format

```
[1 byte:  version_string_length]
[N bytes: version string, e.g. "GFUSB_GM168SEC_APP_10034"]
[M bytes: firmware binary payload]
[4 bytes: trailing CRC32]
```

Global pointer: `[0x180246848]` → firmware struct with data pointer and size.
IAP variant selected by flag at `[0x180246804]`.

---

## 4. McuResetMcu (0x1800a7ae0)

Called after successful firmware write to reboot the MCU from IAP to APP mode.
This is the command that makes the MCU exit IAP mode and boot the newly written APP firmware.

---

## 5. CompareVersion (0x18009ec1c) — When Is WriteApp Needed?

Returns:
- **0**: Versions match → "do not upgrade" → skip WriteApp entirely
- **1**: Version mismatch → firmware update needed → erase + WriteApp
- **4**: Platform mismatch → error
- **5**: Parse error

In normal operation (device already has correct firmware), CompareVersion returns 0
and WriteApp is NEVER called. WriteApp only runs when:
1. Firmware version on device differs from embedded version, OR
2. forceFirmwareUpdate flag is set in registry/config, OR
3. Device is in IAP mode (firmware was erased)

---

## 6. Implications for Linux Driver PSK Enrollment

### The Problem
- PSK write (cmd 0xE0) is REJECTED in APP mode (MCU returns error 1)
- PSK write only works in IAP mode
- To enter IAP mode: McuEraseApp (cmd 0xA4, payload [0x00, 0x32])
- After erase: MCU is in IAP, firmware is gone
- To return to APP mode: must re-flash firmware via WriteApp (cmd 0xF0 + 0xF4)
- Firmware data is 26KB embedded in the Windows DLL (copyrighted)

### Options
1. **Extract firmware from DLL**: Include 26KB firmware blob in Linux driver.
   Legal concern: Goodix firmware is proprietary.

2. **Avoid erase entirely**: Find a way to write PSK in APP mode.
   Not possible per current RE: MCU rejects writes in APP mode.

3. **Use the Windows driver to do initial PSK enrollment**: User connects to Windows once,
   Windows driver handles erase + WriteApp + ProcessPsk, then Linux uses the PSK.
   This is the current working approach.

4. **Extract firmware from device before erase**: Read firmware via MCU command,
   save it, erase, write PSK, re-flash saved firmware. Unknown if firmware read
   command exists.

5. **Distribute firmware separately**: User downloads Goodix driver package,
   our tool extracts firmware from Wbdi.dll and uses it for enrollment.
   Still has legal concerns but avoids embedding in our repo.
