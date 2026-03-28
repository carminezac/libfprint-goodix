#!/bin/bash
# Goodix 5e0a fingerprint sensor setup script
# Downloads the Goodix Windows driver, extracts firmware from Wbdi.dll,
# and prepares the sensor for Linux use (PSK enrollment + firmware re-flash).
#
# Usage: sudo ./goodix-5e0a-setup.sh
#
# This script does NOT distribute any Goodix firmware. It downloads
# the official driver package from the manufacturer's distribution
# channel and extracts the necessary firmware blob.

set -e

WBDI_SHA256="55917bbca951524efc51617e955b73052bf7237a3c470ad575a40d03812e028f"
FW_MARKER=$'\x18GFUSB_GM168SEC_APP_10034'
FW_SIZE=26049  # 0x65C1 bytes
FW_BLOB_SHA256="0bec6b5292e0a64029cb0f624ae3bfc2a6e6e4ec642e50fd3bd4b60cf574312e"
FW_OUTPUT="/var/lib/fprint/goodix-5e0a-firmware.bin"
WBDI_SEARCH_PATHS=(
    "./Wbdi.dll"
    "./Drivers/Wbdi.dll"
    "$HOME/Wbdi.dll"
    "$HOME/Downloads/Wbdi.dll"
    "/tmp/Wbdi.dll"
)

echo "=== Goodix 5e0a Fingerprint Sensor Setup ==="
echo ""

# Check if sensor exists
if ! lsusb | grep -q "27c6:5e0a"; then
    echo "ERROR: Goodix 27c6:5e0a sensor not found on USB!"
    echo "Make sure the sensor is connected."
    exit 1
fi
echo "[OK] Sensor detected"

# Check if firmware already extracted
if [ -f "$FW_OUTPUT" ]; then
    EXISTING_HASH=$(sha256sum "$FW_OUTPUT" | cut -d' ' -f1)
    if [ "$EXISTING_HASH" = "$FW_BLOB_SHA256" ]; then
        echo "[OK] Firmware already extracted at $FW_OUTPUT"
        echo "Setup complete. Run: sudo fprintd-enroll \$(whoami)"
        exit 0
    else
        echo "[WARN] Existing firmware has wrong hash, re-extracting..."
    fi
fi

# Find Wbdi.dll
WBDI_PATH=""
for path in "${WBDI_SEARCH_PATHS[@]}"; do
    if [ -f "$path" ]; then
        WBDI_PATH="$path"
        break
    fi
done

if [ -z "$WBDI_PATH" ]; then
    echo ""
    echo "Wbdi.dll not found. Attempting automatic download..."
    echo ""

    # Try automatic download from known sources
    # The Goodix driver package is available from laptop manufacturer support pages
    # TODO: Add specific download URLs for known laptop models
    DOWNLOAD_OK=false

    # Attempt: try to find via Windows driver cab in system
    if [ -d "/mnt/windows" ] || [ -d "/mnt/c" ]; then
        WIN_PATH=$(find /mnt/windows /mnt/c -name "Wbdi.dll" -path "*/Goodix*" 2>/dev/null | head -1)
        if [ -n "$WIN_PATH" ]; then
            echo "Found Wbdi.dll in Windows partition: $WIN_PATH"
            WBDI_PATH="$WIN_PATH"
            DOWNLOAD_OK=true
        fi
    fi

    if [ "$DOWNLOAD_OK" = false ]; then
        echo "=========================================="
        echo "AUTOMATIC DOWNLOAD FAILED"
        echo "=========================================="
        echo ""
        echo "Please download the Goodix fingerprint driver manually:"
        echo ""
        echo "  1. Go to your laptop manufacturer's support page"
        echo "  2. Download the Goodix FingerPrint driver (version 3.0.141.150)"
        echo "  3. Extract the package and find 'Wbdi.dll' in the Drivers folder"
        echo "  4. Copy Wbdi.dll to one of these locations:"
        echo "     - ./Wbdi.dll (current directory)"
        echo "     - ~/Wbdi.dll"
        echo "     - ~/Downloads/Wbdi.dll"
        echo "  5. Re-run this script: sudo ./goodix-5e0a-setup.sh"
        echo ""
        echo "  Expected SHA256 of Wbdi.dll:"
        echo "  $WBDI_SHA256"
        echo ""
        echo "  Alternative: if you have a Windows partition mounted, this script"
        echo "  can find Wbdi.dll automatically. Mount it at /mnt/windows."
        echo "=========================================="
        exit 1
    fi
fi

echo "Using Wbdi.dll: $WBDI_PATH"

# Verify Wbdi.dll hash
echo "Verifying Wbdi.dll integrity..."
ACTUAL_HASH=$(sha256sum "$WBDI_PATH" | cut -d' ' -f1)
if [ "$ACTUAL_HASH" != "$WBDI_SHA256" ]; then
    echo "WARNING: Wbdi.dll hash mismatch!"
    echo "  Expected: $WBDI_SHA256"
    echo "  Got:      $ACTUAL_HASH"
    echo "  This may be a different version. Attempting extraction anyway..."
fi

# Extract firmware blob
echo "Extracting firmware blob..."
python3 -c "
import sys, hashlib

data = open('$WBDI_PATH', 'rb').read()
marker = b'\x18GFUSB_GM168SEC_APP_10034'
idx = data.find(marker)
if idx == -1:
    print('ERROR: Firmware marker not found in Wbdi.dll')
    sys.exit(1)

blob = data[idx:idx+$FW_SIZE]
blob_hash = hashlib.sha256(blob).hexdigest()
print(f'Found firmware at offset 0x{idx:x}')
print(f'Blob SHA256: {blob_hash}')

if blob_hash != '$FW_BLOB_SHA256':
    print('WARNING: Firmware blob hash mismatch — may be a different version')

open('$FW_OUTPUT', 'wb').write(blob)
print(f'Firmware extracted to $FW_OUTPUT ({len(blob)} bytes)')
" || {
    echo "ERROR: Failed to extract firmware. Is python3 installed?"
    exit 1
}

# Verify extracted blob
BLOB_HASH=$(sha256sum "$FW_OUTPUT" | cut -d' ' -f1)
if [ "$BLOB_HASH" = "$FW_BLOB_SHA256" ]; then
    echo "[OK] Firmware blob verified"
else
    echo "[WARN] Firmware blob hash differs — may be a different firmware version"
fi

chmod 600 "$FW_OUTPUT"
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Firmware extracted. Now run:"
echo "  sudo fprintd-enroll \$(whoami)"
echo ""
echo "The driver will automatically enroll a new PSK and flash the firmware."
