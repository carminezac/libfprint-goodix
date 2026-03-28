// Goodix Tls driver for libfprint — 5e0a device
//
// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <ashenglandelbro@protonmail.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include "fp-device.h"
#include "fp-image-device.h"
#include "fp-image.h"
#include "fpi-context.h"
#include "fpi-image-device.h"
#include "fpi-image.h"
#include "fpi-ssm.h"

#define FP_COMPONENT "goodixtls5e0a"

#include <glib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodix5e0a.h"

// ---- SecWhiteEncrypt (RE: Wbdi.dll SecWhiteEncrypt @ 0x180005f30) ----

static const guint8 WB_SALT[] = "123GOODIX";   /* 9 bytes */
static const guint8 WB_CONSTANT[16] = {
  0x5c, 0xba, 0x6e, 0x25, 0x81, 0x95, 0x18, 0xde,
  0x2d, 0x53, 0xe9, 0x6d, 0xc0, 0x34, 0x7a, 0xb0
};

/* Encrypt PSK using Goodix whitebox algorithm.
 * Input:  psk (32 bytes)
 * Output: out (96 bytes) = nonce(16) + ciphertext(48) + hmac(32)
 * Returns 0 on success, -1 on failure. */
static int
sec_white_encrypt (const guint8 *psk, gsize psk_len, guint8 *out)
{
  guint8 nonce_input[4 + 9];  /* LE32(len) + "123GOODIX" */
  guint8 hash1[32], hash2[32];
  guint8 nonce[16];
  guint8 nonce_padded[64 + 16];  /* nonce padded to 64 + WB_CONSTANT */
  guint8 padded[48];             /* PKCS7 padded PSK */
  guint8 ciphertext[48];
  guint8 hmac_tag[32];
  unsigned int hmac_len = 32;
  int ct_len = 0, final_len = 0;

  /* Step 1: nonce = SHA256(LE32(psk_len) || "123GOODIX")[:16] */
  nonce_input[0] = (psk_len >>  0) & 0xFF;
  nonce_input[1] = (psk_len >>  8) & 0xFF;
  nonce_input[2] = (psk_len >> 16) & 0xFF;
  nonce_input[3] = (psk_len >> 24) & 0xFF;
  memcpy (nonce_input + 4, WB_SALT, 9);
  SHA256 (nonce_input, 13, hash1);
  memcpy (nonce, hash1, 16);

  /* Step 2: tweak byte[15] — low nibble = (b15 ^ data_len_low) & 0x0f ^ b15 */
  guint8 b15 = nonce[15];
  guint8 dl = psk_len & 0xFF;
  nonce[15] = ((b15 ^ dl) & 0x0F) ^ b15;

  /* Step 3: derive keys — SHA256(nonce_padded_to_64 || WB_CONSTANT) */
  memset (nonce_padded, 0, sizeof (nonce_padded));
  memcpy (nonce_padded, nonce, 16);
  memcpy (nonce_padded + 64, WB_CONSTANT, 16);
  SHA256 (nonce_padded, 80, hash2);

  /* aes_key = hash2[:16], hmac_key = hash2[:32] */

  /* Step 4: PKCS7 pad PSK to 48 bytes (32 + 16 padding of 0x10) */
  memcpy (padded, psk, psk_len);
  guint8 pad_val = 16 - (psk_len % 16);
  if (pad_val == 0) pad_val = 16;
  memset (padded + psk_len, pad_val, pad_val);

  /* Step 5: AES-128-CBC encrypt */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx) return -1;
  EVP_CIPHER_CTX_set_padding (ctx, 0);  /* we handle PKCS7 manually */
  if (EVP_EncryptInit_ex (ctx, EVP_aes_128_cbc (), NULL, hash2, nonce) != 1 ||
      EVP_EncryptUpdate (ctx, ciphertext, &ct_len, padded, psk_len + pad_val) != 1 ||
      EVP_EncryptFinal_ex (ctx, ciphertext + ct_len, &final_len) != 1)
    {
      EVP_CIPHER_CTX_free (ctx);
      return -1;
    }
  ct_len += final_len;
  EVP_CIPHER_CTX_free (ctx);

  /* Step 6: HMAC-SHA256(hash2[:32], ciphertext) */
  HMAC (EVP_sha256 (), hash2, 32, ciphertext, ct_len, hmac_tag, &hmac_len);

  /* Step 7: output = nonce(16) + ciphertext(48) + hmac(32) */
  memcpy (out,      nonce,      16);
  memcpy (out + 16, ciphertext, ct_len);
  memcpy (out + 16 + ct_len, hmac_tag, 32);

  return 0;
}

// ---- PSK Enrollment Protocol ----

/* CRC-32/MPEG-2: poly 0x04C11DB7, init 0xFFFFFFFF, no final XOR, MSB-first.
 * RE: fcn.1800c78a0 in Wbdi.dll */
static guint32
crc32_mpeg2 (const guint8 *data, gsize len)
{
  guint32 crc = 0xFFFFFFFF;
  for (gsize i = 0; i < len; i++)
    {
      crc ^= (guint32)data[i] << 24;
      for (int j = 0; j < 8; j++)
        crc = (crc & 0x80000000) ? (crc << 1) ^ 0x04C11DB7 : crc << 1;
    }
  return crc;
}

/* Compute PMK HMAC for firmware verification.
 * RE: production_get_pmk_hmac @ 0x18003cf9c in Wbdi.dll
 *
 * raw_pmk (68 bytes):
 *   [0x00][psk_len_byte][ZEROS*32][0x00][psk_len_byte][PSK*32]
 *   PSK is ONLY in the second half. First half is zeros.
 *
 * pmk = SHA256(raw_pmk)
 * mod = [1, 2, 3, ..., 64]
 * pmk_hmac = HMAC-SHA256(key=pmk, data=mod)
 *
 * Then for firmware verify:
 * fw_hmac = HMAC-SHA256(key=pmk_hmac, data=write_buf) */
static gboolean
compute_fw_hmac (const guint8 *psk, gsize psk_len,
                 const guint8 *write_buf, gsize write_buf_len,
                 guint8 *out_hmac)
{
  /* Step 1: Build raw_pmk (68 bytes) — RE exact layout */
  guint8 raw_pmk[68];
  memset (raw_pmk, 0, 68);
  raw_pmk[1] = (guint8)psk_len;                  /* offset 1: psk_len byte */
  raw_pmk[0x23] = (guint8)psk_len;               /* offset 35: psk_len byte */
  memcpy (raw_pmk + 0x24, psk, psk_len);          /* offset 36: PSK (second half ONLY) */

  /* Step 2: pmk = SHA256(raw_pmk) */
  guint8 pmk[32];
  SHA256 (raw_pmk, 68, pmk);

  /* Step 3: mod = [1, 2, ..., 64] */
  guint8 mod[64];
  for (int i = 0; i < 64; i++)
    mod[i] = (guint8)(i + 1);

  /* Step 4: pmk_hmac = HMAC-SHA256(key=pmk, data=mod) */
  guint8 pmk_hmac[32];
  unsigned int hmac_len = 32;
  HMAC (EVP_sha256 (), pmk, 32, mod, 64, pmk_hmac, &hmac_len);

  /* Step 5: fw_hmac = HMAC-SHA256(key=pmk_hmac, data=write_buf) */
  HMAC (EVP_sha256 (), pmk_hmac, 32, write_buf, write_buf_len, out_hmac, &hmac_len);

  return TRUE;
}

static const guint8 PRE_FLAGS[10] = {
  0x56, 0xa5, 0xbb, 0x95, 0x6b, 0x7c, 0x8d, 0x9e, 0x00, 0x00
};

#define TLV_PSK_DPAPI    0xBB010002
#define TLV_PSK_WHITEBOX 0xBB010003
#define CMD_PSK_WRITE    0xE0
#define CMD_PSK_READ     0xE4
#define PSK_CHUNK_SIZE   256

/* Build the PSK write payload: PRE_FLAGS + TLV(DPAPI) + TLV(whitebox).
 * fake_dpapi: 32 bytes (MCU stores opaquely, doesn't decrypt).
 * wb_blob: 96 bytes from sec_white_encrypt.
 * out: must be at least 154 bytes. Returns payload length. */
static gsize
build_psk_payload (const guint8 *fake_dpapi, const guint8 *wb_blob, guint8 *out)
{
  guint8 *p = out;

  memcpy (p, PRE_FLAGS, 10);
  p += 10;

  /* TLV1: DPAPI blob */
  guint32 t1 = GUINT32_TO_LE (TLV_PSK_DPAPI);
  guint32 l1 = GUINT32_TO_LE (32);
  memcpy (p, &t1, 4); p += 4;
  memcpy (p, &l1, 4); p += 4;
  memcpy (p, fake_dpapi, 32); p += 32;

  /* TLV2: Whitebox encrypted PSK */
  guint32 t2 = GUINT32_TO_LE (TLV_PSK_WHITEBOX);
  guint32 l2 = GUINT32_TO_LE (96);
  memcpy (p, &t2, 4); p += 4;
  memcpy (p, &l2, 4); p += 4;
  memcpy (p, wb_blob, 96); p += 96;

  return (gsize)(p - out);  /* 154 bytes */
}

/* Build a chunk buffer: [total_len:4][chunk_len:4][offset:4][data].
 * Returns total size of chunk buffer (12 + data_len). */
static gsize
build_chunk (const guint8 *payload, gsize total_len, gsize offset,
             gsize chunk_len, guint8 *out)
{
  guint32 total_le = GUINT32_TO_LE ((guint32)total_len);
  guint32 chunk_le = GUINT32_TO_LE ((guint32)chunk_len);
  guint32 off_le   = GUINT32_TO_LE ((guint32)offset);

  memcpy (out + 0, &total_le, 4);
  memcpy (out + 4, &chunk_le, 4);
  memcpy (out + 8, &off_le, 4);
  memcpy (out + 12, payload + offset, chunk_len);

  return 12 + chunk_len;
}

typedef unsigned short Goodix5e0aPix;

struct _FpiDeviceGoodixTls5e0a
{
  FpiDeviceGoodixTls parent;

  guint8 image_psk[32];
  gboolean has_image_psk;

  Goodix5e0aPix *calibration_img;  // baseline frame (no finger) for subtraction

  guint8 *prev_scan_data;   // previous scan raw data for diversity check
  guint16 prev_scan_size;

  guint8 fdt_down_payload[35];  // dynamically computed FDT_DOWN payload
  guint8 fdt_up_payload[35];    // dynamically computed FDT_UP payload

  gboolean in_iap_mode;          // TRUE after erase_app, detected via fw version
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls5e0a, fpi_device_goodixtls5e0a, FPI,
                      DEVICE_GOODIXTLS5E0A, FpiDeviceGoodixTls);

G_DEFINE_TYPE (FpiDeviceGoodixTls5e0a, fpi_device_goodixtls5e0a,
               FPI_TYPE_DEVICE_GOODIXTLS);

// Forward declarations
static void goodix_5e0a_decode_frame (Goodix5e0aPix *frame, guint32 raw_size, const guint8 *raw_frame);
static void on_calibration_image (FpDevice *dev, guint8 *data, guint16 len, gpointer user_data, GError *err);

// ---- CALIBRATION ----

static void
on_calibration_image (FpDevice *dev, guint8 *data, guint16 len,
                      gpointer user_data, GError *err)
{
  FpiSsm *ssm = user_data;

  if (err)
    {
      fp_warn ("Calibration capture failed (non-fatal): %s", err->message);
      g_error_free (err);
      fpi_ssm_next_state (ssm);
      return;
    }

  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (len < GOODIX_5E0A_RAW_FRAME_SIZE)
    {
      fp_warn ("Calibration data too small: %d", len);
      fpi_ssm_next_state (ssm);
      return;
    }

  if (!self->calibration_img)
    self->calibration_img = calloc (GOODIX_5E0A_FRAME_SIZE,
                                    sizeof (Goodix5e0aPix));

  goodix_5e0a_decode_frame (self->calibration_img,
                            GOODIX_5E0A_RAW_FRAME_SIZE, data);
  fp_dbg ("Calibration frame captured (%d pixels)", GOODIX_5E0A_FRAME_SIZE);
  fpi_ssm_next_state (ssm);
}

static void
linear_subtract_5e0a (Goodix5e0aPix *src, const Goodix5e0aPix *baseline,
                      guint16 len)
{
  // Subtract baseline from scan: result = clamp(scan - baseline, 0, max)
  // This removes fixed pattern noise
  for (guint16 i = 0; i < len; i++)
    {
      if (src[i] > baseline[i])
        src[i] = src[i] - baseline[i];
      else
        src[i] = 0;
    }
}

// ---- HELPERS ----

static void
check_none_5e0a (FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (user_data, error);
      return;
    }
  fpi_ssm_next_state (user_data);
}

static void
check_none_cmd_5e0a (FpDevice *dev, guint8 *data, guint16 len,
                     gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }
  fpi_ssm_next_state (ssm);
}

// ---- FRAME DECODE ----

// Decode the 4/6 byte packing used by Goodix sensors.
// The 5e0a raw frame has NO 8-byte header / 5-byte footer (unlike 5110).
static void
goodix_5e0a_decode_frame (Goodix5e0aPix *frame, guint32 raw_size,
                          const guint8 *raw_frame)
{
  Goodix5e0aPix *pix = frame;

  for (guint32 i = 0; i < raw_size; i += 6)
    {
      const guint8 *chunk = raw_frame + i;
      *pix++ = ((chunk[0] & 0xf) << 8) + chunk[1];
      *pix++ = (chunk[3] << 4) + (chunk[0] >> 4);
      *pix++ = ((chunk[5] & 0xf) << 8) + chunk[2];
      *pix++ = (chunk[4] << 4) + (chunk[5] >> 4);
    }
}

// Compare function for qsort of Goodix5e0aPix values
static int
cmp_pix (const void *a, const void *b)
{
  Goodix5e0aPix pa = *(const Goodix5e0aPix *) a;
  Goodix5e0aPix pb = *(const Goodix5e0aPix *) b;
  return (pa > pb) - (pa < pb);
}

static void
goodix_5e0a_squash_frame (Goodix5e0aPix *frame, guint8 *squashed,
                          guint16 frame_size)
{
  // Elan-style "thirds" normalization for small sensors.
  // Instead of simple linear min/max scaling, we divide pixels into 3 groups
  // by intensity percentile and map each group to a different output range.
  // This preserves more contrast in the ridge/valley boundary region where
  // most fingerprint detail lives.
  //
  // First, collect only active (non-dead-zone) pixels for percentile calc.
  Goodix5e0aPix *active = g_malloc (frame_size * sizeof (Goodix5e0aPix));
  int n_active = 0;

  for (int i = 0; i < frame_size; i++)
    {
      if (frame[i] != 0)
        active[n_active++] = frame[i];
    }

  if (n_active < 4)
    {
      // Degenerate case: nearly all dead pixels
      memset (squashed, 0xff, frame_size);
      g_free (active);
      return;
    }

  qsort (active, n_active, sizeof (Goodix5e0aPix), cmp_pix);

  // Percentile boundaries (same as elan driver):
  //   lvl0 = minimum,  lvl1 = 30th percentile,
  //   lvl2 = 65th percentile,  lvl3 = maximum
  Goodix5e0aPix lvl0 = active[0];
  Goodix5e0aPix lvl1 = active[n_active * 3 / 10];
  Goodix5e0aPix lvl2 = active[n_active * 65 / 100];
  Goodix5e0aPix lvl3 = active[n_active - 1];

  g_free (active);

  // Avoid division by zero on flat regions
  if (lvl1 == lvl0) lvl1 = lvl0 + 1;
  if (lvl2 == lvl1) lvl2 = lvl1 + 1;
  if (lvl3 == lvl2) lvl3 = lvl2 + 1;

  for (int i = 0; i < frame_size; i++)
    {
      if (frame[i] == 0)
        {
          // Dead zone sentinel — NBIS treats white as background
          squashed[i] = 0xff;
          continue;
        }

      Goodix5e0aPix px = frame[i];
      guint32 val;

      // Map to 3 output ranges: [0-99], [99-155], [155-254]
      // The middle range (ridges/valleys boundary) gets compressed,
      // giving more contrast to the extremes where detail matters.
      if (px < lvl1)
        val = (px - lvl0) * 99 / (lvl1 - lvl0);
      else if (px < lvl2)
        val = 99 + (px - lvl1) * 56 / (lvl2 - lvl1);
      else
        val = 155 + (px - lvl2) * 99 / (lvl3 - lvl2);

      if (val > 254)
        val = 254;
      squashed[i] = (guint8) val;
    }
}

// Unsharp mask filter to enhance ridge contrast for NBIS minutiae detection.
// The sensor produces low-contrast images; sharpening makes ridges and valleys
// more distinct so NBIS can reliably detect minutiae.
static void
goodix_5e0a_unsharp_mask (guint8 *out, const guint8 *in,
                          int width, int height,
                          int radius, double strength)
{
  for (int y = 0; y < height; y++)
    {
      for (int x = 0; x < width; x++)
        {
          int idx = y * width + x;
          if (in[idx] == 0xff)
            {
              out[idx] = 0xff;
              continue;
            }

          // Box blur in the neighborhood, excluding dead zone pixels
          int sum = 0, cnt = 0;
          for (int dy = -radius; dy <= radius; dy++)
            {
              int ny = y + dy;
              if (ny < 0 || ny >= height)
                continue;
              for (int dx = -radius; dx <= radius; dx++)
                {
                  int nx = x + dx;
                  if (nx < 0 || nx >= width)
                    continue;
                  guint8 px = in[ny * width + nx];
                  if (px != 0xff)
                    {
                      sum += px;
                      cnt++;
                    }
                }
            }

          if (cnt == 0)
            {
              out[idx] = in[idx];
              continue;
            }

          double blur = (double) sum / cnt;
          double sharp = in[idx] + strength * (in[idx] - blur);
          if (sharp < 0.0)
            sharp = 0.0;
          if (sharp > 254.0)
            sharp = 254.0;
          out[idx] = (guint8) sharp;
        }
    }
}

// ---- PSK ENROLLMENT SUB-SSM ----
// Triggered when ACTIVATE_CHECK_PSK detects missing/invalid PSK.
// Flow: write chunk (0xE0) → confirm (0xE4) → verify hash → save file.

enum psk_enroll_states {
  PSK_ENROLL_ERASE_APP,
  PSK_ENROLL_ERASE_WAIT,
  PSK_ENROLL_WRITE_CHUNK,
  PSK_ENROLL_CONFIRM_CHUNK,
  PSK_ENROLL_VERIFY,
  PSK_ENROLL_WRITE_FW,         /* cmd 0xF0 — write APP firmware (chunked) */
  PSK_ENROLL_VERIFY_FW,        /* cmd 0xF4 — HMAC verify firmware */
  PSK_ENROLL_RESET_MCU,        /* McuResetMcu — reboot to APP mode */
  PSK_ENROLL_RESET_WAIT,       /* wait for MCU reboot */
  PSK_ENROLL_SAVE,

  PSK_ENROLL_NUM_STATES,
};

#define PSK_ERASE_MAX_RETRIES 2

/* Firmware path — extracted from Wbdi.dll by setup script */
#define FW_BLOB_PATH "/var/lib/fprint/goodix-5e0a-firmware.bin"
#define FW_CHUNK_SIZE 256
#define FW_MODE_APP 2

typedef struct {
  guint8 new_psk[32];
  guint8 chunk_buf[12 + PSK_CHUNK_SIZE];
  gsize  chunk_buf_len;
  FpiSsm *parent_ssm;
  guint8 erase_retries;
  gboolean need_erase;

  /* Firmware re-flash state */
  guint8 *fw_buf;       /* firmware write buffer (header + payload) */
  gsize   fw_buf_len;
  gsize   fw_offset;    /* current write offset */
} PskEnrollCtx;

static void
on_psk_write_response (FpDevice *dev, guint8 *data, guint16 length,
                       gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_err ("PSK write (0xE0) failed: %s", error->message);
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (length < 1 || data[0] != 0)
    {
      PskEnrollCtx *ctx = fpi_ssm_get_data (ssm);
      fp_warn ("PSK write rejected (status=%d) — need erase_app",
               length > 0 ? data[0] : -1);
      if (ctx->erase_retries < PSK_ERASE_MAX_RETRIES)
        {
          ctx->need_erase = TRUE;
          fpi_ssm_jump_to_state (ssm, PSK_ENROLL_ERASE_APP);
          return;
        }
      fp_err ("PSK write failed after %d erase retries", ctx->erase_retries);
      fpi_ssm_mark_failed (ssm,
        g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                     "PSK write rejected after max erase retries"));
      return;
    }
  fp_dbg ("PSK write chunk accepted");
  fpi_ssm_next_state (ssm);
}

static void
on_erase_app_response (FpDevice *dev, guint8 *data, guint16 length,
                       gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  PskEnrollCtx *ctx = fpi_ssm_get_data (ssm);

  if (error)
    {
      fp_warn ("erase_app error: %s — retrying", error->message);
      g_error_free (error);
    }
  /* Response: data[0]==1 means success for erase_app (inverted convention) */
  fp_info ("erase_app sent (attempt %d/%d), waiting for MCU reboot...",
           ctx->erase_retries, PSK_ERASE_MAX_RETRIES);
  ctx->erase_retries++;
  fpi_ssm_next_state (ssm);
}

static void
on_erase_wait_done (FpDevice *dev, gpointer data)
{
  FpiSsm *ssm = data;
  fp_dbg ("erase_app wait complete, retrying PSK write...");
  fpi_ssm_next_state (ssm);
}

static void
on_psk_confirm_response (FpDevice *dev, guint8 *data, guint16 length,
                         gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_warn ("PSK confirm (0xE4) error: %s — continuing", error->message);
      g_error_free (error);
    }
  fpi_ssm_next_state (ssm);
}

static void
on_fw_write_chunk_response (FpDevice *dev, guint8 *data, guint16 length,
                            gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  PskEnrollCtx *ctx = fpi_ssm_get_data (ssm);

  if (error)
    {
      fp_err ("Firmware write (0xF0) failed: %s", error->message);
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  ctx->fw_offset += FW_CHUNK_SIZE;
  if (ctx->fw_offset < ctx->fw_buf_len)
    {
      /* More chunks to send — stay in same state */
      fp_dbg ("  fw write: %zu/%zu bytes", ctx->fw_offset, ctx->fw_buf_len);
      fpi_ssm_jump_to_state (ssm, PSK_ENROLL_WRITE_FW);
    }
  else
    {
      fp_info ("Firmware write complete (%zu bytes)", ctx->fw_buf_len);
      fpi_ssm_next_state (ssm);
    }
}

static void
on_fw_verify_response (FpDevice *dev, guint8 *data, guint16 length,
                       gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_err ("Firmware verify (0xF4) error: %s", error->message);
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  /* RE: DLL checks "if (check_ok != 0) → success" */
  if (length < 1 || data[0] == 0)
    {
      fp_err ("Firmware verify FAILED (status=%d)", length > 0 ? data[0] : -1);
      fpi_ssm_mark_failed (ssm,
        g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED, "Firmware HMAC verification failed"));
      return;
    }

  fp_info ("Firmware verified OK (status=%d)", data[0]);
  fpi_ssm_next_state (ssm);
}

static void
on_mcu_reset_response (FpDevice *dev, guint8 *data, guint16 length,
                       gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;
  if (error)
    {
      fp_warn ("MCU reset response error: %s — continuing", error->message);
      g_error_free (error);
    }
  fp_info ("MCU reset sent, waiting for reboot to APP mode...");
  fpi_ssm_next_state (ssm);
}

static void
on_reset_wait_done (FpDevice *dev, gpointer data)
{
  FpiSsm *ssm = data;
  fp_dbg ("MCU reboot wait complete");
  fpi_ssm_next_state (ssm);
}

/* Load firmware blob from file, prepare write buffer with header.
 * RE format: [header_crc:4][payload_size:4][payload_crc:4][firmware_payload]
 * Returns 0 on success. */
static int
load_firmware_blob (PskEnrollCtx *ctx)
{
  gchar *fw_data = NULL;
  gsize fw_len = 0;

  if (!g_file_get_contents (FW_BLOB_PATH, &fw_data, &fw_len, NULL))
    {
      fp_err ("Cannot read firmware file %s", FW_BLOB_PATH);
      return -1;
    }

  if (fw_len < 30)
    {
      fp_err ("Firmware file too small: %zu bytes", fw_len);
      g_free (fw_data);
      return -1;
    }

  /* Parse: [1 byte ver_len][ver_string][payload][4 byte trailing CRC] */
  guint8 ver_len = ((guint8 *)fw_data)[0];
  gsize payload_offset = 1 + ver_len;
  gsize payload_size = fw_len - payload_offset - 4;

  fp_dbg ("Firmware: ver_len=%d, payload=%zu bytes", ver_len, payload_size);

  /* Build write buffer: [header_crc:4][payload_size:4][payload_crc:4][payload] */
  ctx->fw_buf_len = 12 + payload_size;
  ctx->fw_buf = g_malloc (ctx->fw_buf_len);
  ctx->fw_offset = 0;

  guint32 *hdr = (guint32 *)ctx->fw_buf;
  hdr[1] = GUINT32_TO_LE ((guint32)payload_size);

  /* CRC-32/MPEG-2: poly 0x04C11DB7, init 0xFFFFFFFF, no final XOR, MSB-first.
   * RE: fcn.1800c78a0 in Wbdi.dll */
  const guint8 *payload = (const guint8 *)fw_data + payload_offset;

  guint32 payload_crc = crc32_mpeg2 (payload, payload_size);
  hdr[2] = GUINT32_TO_LE (payload_crc);

  guint32 hdr_crc = crc32_mpeg2 ((const guint8 *)&hdr[1], 8);
  hdr[0] = GUINT32_TO_LE (hdr_crc);

  memcpy (ctx->fw_buf + 12, payload, payload_size);
  g_free (fw_data);

  fp_dbg ("Firmware buffer ready: %zu bytes (12 header + %zu payload)",
          ctx->fw_buf_len, payload_size);
  return 0;
}

static void
on_psk_verify_hash (FpDevice *dev, gboolean success, guint32 flags,
                    guint8 *device_hash, guint16 length, gpointer user_data,
                    GError *error)
{
  FpiSsm *ssm = user_data;
  PskEnrollCtx *ctx = fpi_ssm_get_data (ssm);

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!success || length < 32)
    {
      fpi_ssm_mark_failed (ssm,
        g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED, "PSK verify: read hash failed"));
      return;
    }

  guint8 expected[32];
  SHA256 (ctx->new_psk, 32, expected);

  if (memcmp (device_hash, expected, 32) != 0)
    {
      fp_err ("PSK verify: hash MISMATCH!");
      fpi_ssm_mark_failed (ssm,
        g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED, "PSK hash mismatch after write"));
      return;
    }

  fp_info ("PSK verified successfully on device");
  fpi_ssm_next_state (ssm);
}

static void
psk_enroll_run (FpiSsm *ssm, FpDevice *dev)
{
  PskEnrollCtx *ctx = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case PSK_ENROLL_ERASE_APP:
      if (!ctx->need_erase)
        {
          /* First attempt: skip erase, try write directly */
          fpi_ssm_jump_to_state (ssm, PSK_ENROLL_WRITE_CHUNK);
          break;
        }
      fp_warn ("PSK enrollment: sending erase_app (0xA4) [0x00, 0x32]...");
      {
        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_erase_app_response);
        cb_info->user_data = ssm;
        guint8 erase_payload[] = { 0x00, 0x32 };
        goodix_send_protocol (dev, 0xa4, erase_payload,
                              sizeof (erase_payload), NULL, TRUE,
                              3000, FALSE,  /* reply=FALSE: MCU resets, won't send data response */
                              goodix_receive_none, cb_info);
      }
      break;

    case PSK_ENROLL_ERASE_WAIT:
      /* Wait 2 seconds for MCU to reboot into IAP mode */
      fp_info ("Waiting 2s for MCU reboot...");
      fpi_device_add_timeout (dev, 2000, on_erase_wait_done, ssm, NULL);
      break;

    case PSK_ENROLL_WRITE_CHUNK:
      fp_dbg ("PSK enrollment: writing chunk (0xE0)...");
      {
        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_psk_write_response);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, CMD_PSK_WRITE,
                              ctx->chunk_buf, ctx->chunk_buf_len,
                              NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case PSK_ENROLL_CONFIRM_CHUNK:
      fp_dbg ("PSK enrollment: confirming chunk (0xE4)...");
      {
        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_psk_confirm_response);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, CMD_PSK_READ,
                              ctx->chunk_buf, ctx->chunk_buf_len,
                              NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case PSK_ENROLL_VERIFY:
      fp_dbg ("PSK enrollment: verifying hash...");
      {
        /* Read hash using correct 16-byte payload format */
        guint8 psk_read_payload[16];
        guint32 len_le = GUINT32_TO_LE (32);
        guint32 off_le = GUINT32_TO_LE (0);
        guint32 flags_le = GUINT32_TO_LE (GOODIX_5E0A_PSK_FLAGS);
        guint32 zero = 0;
        memcpy (psk_read_payload + 0,  &len_le,   4);
        memcpy (psk_read_payload + 4,  &off_le,   4);
        memcpy (psk_read_payload + 8,  &flags_le, 4);
        memcpy (psk_read_payload + 12, &zero,     4);

        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_psk_verify_hash);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, GOODIX_CMD_PRESET_PSK_READ,
                              psk_read_payload, sizeof (psk_read_payload),
                              NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                              goodix_receive_preset_psk_read, cb_info);
      }
      break;

    case PSK_ENROLL_WRITE_FW:
      {
        /* Load firmware on first entry */
        if (ctx->fw_buf == NULL)
          {
            if (load_firmware_blob (ctx) != 0)
              {
                fp_err ("No firmware blob — cannot re-flash MCU");
                fpi_ssm_mark_failed (ssm,
                  g_error_new (G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                    "Firmware blob not found at %s. Run goodix-5e0a-setup.sh first.",
                    FW_BLOB_PATH));
                break;
              }
          }

        gsize remaining = ctx->fw_buf_len - ctx->fw_offset;
        gsize chunk = remaining < FW_CHUNK_SIZE ? remaining : FW_CHUNK_SIZE;

        fp_dbg ("Writing firmware chunk: offset=%zu, chunk=%zu, total=%zu",
                ctx->fw_offset, chunk, ctx->fw_buf_len);

        /* Build 0xF0 packet: [offset:4][chunk_len:4][mode:4][data] */
        guint8 fw_pkt[12 + FW_CHUNK_SIZE];
        guint32 off_le = GUINT32_TO_LE ((guint32)ctx->fw_offset);
        guint32 len_le = GUINT32_TO_LE ((guint32)chunk);
        guint32 mode_le = GUINT32_TO_LE (FW_MODE_APP);
        memcpy (fw_pkt + 0, &off_le, 4);
        memcpy (fw_pkt + 4, &len_le, 4);
        memcpy (fw_pkt + 8, &mode_le, 4);
        memcpy (fw_pkt + 12, ctx->fw_buf + ctx->fw_offset, chunk);

        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_fw_write_chunk_response);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, 0xf0, fw_pkt, 12 + chunk,
                              NULL, TRUE, 3000, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case PSK_ENROLL_VERIFY_FW:
      fp_info ("Verifying firmware (0xF4)...");
      {
        /* Compute HMAC over write_buf using correct PMK derivation */
        guint8 fw_hmac[32];
        compute_fw_hmac (ctx->new_psk, 32, ctx->fw_buf, ctx->fw_buf_len, fw_hmac);

        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_fw_verify_response);
        cb_info->user_data = ssm;
        /* RE: DLL sends ONLY 32-byte HMAC via cmd 0xF4 */
        goodix_send_protocol (dev, 0xf4, fw_hmac, 32,
                              NULL, TRUE, 3000, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case PSK_ENROLL_RESET_MCU:
      fp_info ("Resetting MCU to APP mode...");
      {
        GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
        cb_info->callback = G_CALLBACK (on_mcu_reset_response);
        cb_info->user_data = ssm;
        /* McuResetMcu sends a reset command. From RE: fcn.1800a7ae0
         * The exact command byte isn't in our RE — try 0xA2 with [0x05, 0x14]
         * which is ResetFingerPrint, or a NOP to trigger MCU self-reset. */
        guint8 reset_payload[] = { 0x05, 0x14 };
        goodix_send_protocol (dev, 0xa2, reset_payload,
                              sizeof (reset_payload), NULL, TRUE,
                              3000, FALSE,
                              goodix_receive_none, cb_info);
      }
      break;

    case PSK_ENROLL_RESET_WAIT:
      fp_info ("Waiting 3s for MCU reboot to APP mode...");
      fpi_device_add_timeout (dev, 3000, on_reset_wait_done, ssm, NULL);
      break;

    case PSK_ENROLL_SAVE:
      fp_dbg ("PSK enrollment: saving to file...");
      {
        FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
        const char *psk_path = "/var/lib/fprint/goodix-5e0a.psk";

        /* Convert PSK to hex string */
        gchar hex[65];
        for (int i = 0; i < 32; i++)
          g_snprintf (hex + i * 2, 3, "%02x", ctx->new_psk[i]);

        /* Create directory if needed */
        g_mkdir_with_parents ("/var/lib/fprint", 0700);

        /* Write hex PSK to file */
        FILE *f = fopen (psk_path, "w");
        if (f)
          {
            fprintf (f, "%s\n", hex);
            fclose (f);
            chmod (psk_path, 0600);
            fp_info ("PSK saved to %s", psk_path);

            /* Load into device context */
            memcpy (self->image_psk, ctx->new_psk, 32);
            self->has_image_psk = TRUE;
          }
        else
          {
            fp_warn ("Failed to save PSK to %s (errno=%d: %s) — enrollment worked but PSK is ephemeral",
                     psk_path, errno, strerror (errno));
            /* Still load into memory for this session */
            memcpy (self->image_psk, ctx->new_psk, 32);
            self->has_image_psk = TRUE;
          }

        fpi_ssm_next_state (ssm);
      }
      break;
    }
}

static void
psk_enroll_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  PskEnrollCtx *ctx = fpi_ssm_get_data (ssm);
  FpiSsm *parent = ctx->parent_ssm;
  g_free (ctx->fw_buf);
  g_free (ctx);

  if (error)
    {
      fp_err ("PSK enrollment failed: %s", error->message);
      fpi_ssm_mark_failed (parent, error);
      return;
    }

  fp_info ("PSK enrollment completed successfully");
  fpi_ssm_next_state (parent);
}

/* Start PSK enrollment: generates random PSK, encrypts, writes to sensor.
 * parent_ssm will be advanced on success or failed on error. */
static void
start_psk_enrollment (FpDevice *dev, FpiSsm *parent_ssm)
{
  PskEnrollCtx *ctx = g_new0 (PskEnrollCtx, 1);
  ctx->parent_ssm = parent_ssm;

  /* Generate random PSK */
  if (RAND_bytes (ctx->new_psk, 32) != 1)
    {
      fp_err ("Failed to generate random PSK");
      g_free (ctx);
      fpi_ssm_mark_failed (parent_ssm,
        g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED, "RAND_bytes failed"));
      return;
    }

  g_autofree gchar *hex = data_to_str (ctx->new_psk, 32);
  fp_info ("Generated new PSK: 0x%s", hex);

  /* Whitebox encrypt */
  guint8 wb_blob[96];
  if (sec_white_encrypt (ctx->new_psk, 32, wb_blob) != 0)
    {
      fp_err ("SecWhiteEncrypt failed");
      g_free (ctx);
      fpi_ssm_mark_failed (parent_ssm,
        g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED, "SecWhiteEncrypt failed"));
      return;
    }
  fp_dbg ("Whitebox encrypted: 96 bytes");

  /* Build payload */
  guint8 payload[160];
  guint8 fake_dpapi[32] = {0};
  gsize payload_len = build_psk_payload (fake_dpapi, wb_blob, payload);
  fp_dbg ("PSK payload: %zu bytes", payload_len);

  /* Build single chunk (payload < 256, so one chunk) */
  ctx->chunk_buf_len = build_chunk (payload, payload_len, 0, payload_len,
                                    ctx->chunk_buf);

  /* Start enrollment SSM */
  FpiSsm *ssm = fpi_ssm_new (dev, psk_enroll_run, PSK_ENROLL_NUM_STATES);
  fpi_ssm_set_data (ssm, ctx, NULL);
  fpi_ssm_start (ssm, psk_enroll_complete);
}

// ---- ACTIVATION STATE MACHINE ----

/* Activation follows the RE exactly:
 *
 * Phase 1 (always):
 *   NOP → ENABLE → NOP → FW_VERSION
 *
 * Phase 2 (branch on IAP detection):
 *   APP mode: RESET → OTP → CHECK_PSK → CONFIG → CMD_TLS → POV → IMG_TLS → DONE
 *   IAP mode: CHECK_PSK (triggers enrollment → write PSK → reboot → restart)
 *
 * After PSK enrollment in IAP mode, the MCU reboots to APP mode.
 * The driver must restart activation from scratch. */
enum activate_5e0a_states {
  ACTIVATE_READ_AND_NOP1,
  ACTIVATE_ENABLE_CHIP,
  ACTIVATE_NOP2,
  ACTIVATE_CHECK_FW_VERSION,   /* 0xA8 — detect IAP mode */
  ACTIVATE_RESET_SENSOR,       /* 0xA2 — skip in IAP mode */
  ACTIVATE_READ_OTP,           /* 0xA6 — skip in IAP mode */
  ACTIVATE_CHECK_PSK,          /* 0xE4 — always */
  ACTIVATE_UPLOAD_CONFIG,      /* 0x90 — skip in IAP mode */
  ACTIVATE_CMD_TLS,            /* 0xD0 — skip in IAP mode */
  ACTIVATE_POV_IMAGE_CHECK,    /* 0xD6 — skip in IAP mode */
  ACTIVATE_IMG_TLS,            /* 0xD0 — skip in IAP mode */
  ACTIVATE_DONE,

  ACTIVATE_5E0A_NUM_STATES,
};

static void
on_fw_version_5e0a (FpDevice *dev, gchar *firmware, gpointer user_data,
                     GError *error)
{
  FpiSsm *ssm = user_data;
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (error)
    {
      fp_warn ("Firmware version read failed: %s — assuming APP mode", error->message);
      g_error_free (error);
      self->in_iap_mode = FALSE;
      fpi_ssm_next_state (ssm);
      return;
    }

  fp_info ("Firmware: %s", firmware ? firmware : "(null)");

  /* RE: IsInIAPMode checks if version contains "IAP" or "TESTIAP" */
  if (firmware && (strstr (firmware, "IAP") != NULL))
    {
      fp_warn ("MCU is in IAP (bootloader) mode");
      self->in_iap_mode = TRUE;
    }
  else
    {
      self->in_iap_mode = FALSE;
    }

  fpi_ssm_next_state (ssm);
}

static void
on_psk_read_5e0a (FpDevice *dev, gboolean success, guint32 flags,
                  guint8 *device_hash, guint16 length, gpointer user_data,
                  GError *error)
{
  FpiSsm *ssm = user_data;
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (error)
    {
      fp_warn ("PSK read error: %s — starting enrollment", error->message);
      g_error_free (error);
      start_psk_enrollment (dev, ssm);
      return;
    }

  if (!success || length < 32)
    {
      fp_warn ("PSK read failed (len=%d) — starting enrollment", length);
      start_psk_enrollment (dev, ssm);
      return;
    }

  g_autofree gchar *hash_str = data_to_str (device_hash, length);
  fp_dbg ("Device PSK hash: 0x%s", hash_str);

  if (self->has_image_psk)
    {
      guint8 expected[32];
      SHA256 (self->image_psk, 32, expected);
      if (memcmp (device_hash, expected, 32) == 0)
        {
          fp_info ("PSK verified — file matches device");
          fpi_ssm_next_state (ssm);
          return;
        }
      fp_warn ("PSK mismatch — starting auto-enrollment");
    }
  else
    {
      fp_info ("No PSK file — starting auto-enrollment");
    }

  start_psk_enrollment (dev, ssm);
}

static void
on_cmd_tls_complete (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_err ("Command TLS init failed: %s", error->message);
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fp_dbg ("Command TLS established");
  fpi_ssm_next_state (ssm);
}

static void
on_pov_image_check_done (FpDevice *dev, guint8 *data, guint16 len,
                         gpointer ssm, GError *err)
{
  if (err)
    {
      fp_warn ("POV image check failed: %s — continuing anyway", err->message);
      g_error_free (err);
    }
  else
    {
      fp_dbg ("POV image check OK");
    }
  fpi_ssm_next_state (ssm);
}

static void
on_img_tls_complete (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_err ("Image TLS init failed: %s", error->message);
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fp_dbg ("Image TLS established");
  fpi_ssm_next_state (ssm);
}

/* OTP callback: extract tcode/diff, patch config, store DAC */
static void
on_read_otp_5e0a (FpDevice *dev, guint8 *data, guint16 length,
                   gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_warn ("OTP read failed: %s — continuing with default config", error->message);
      g_error_free (error);
      fpi_ssm_next_state (ssm);
      return;
    }

  if (length >= 64)
    {
      guint8 tcode_byte = data[0x2a];
      guint8 tcode_comp = data[0x2b];
      fp_dbg ("OTP[0x2a]=0x%02x OTP[0x2b]=0x%02x DAC=%02x,%02x,%02x,%02x",
              tcode_byte, tcode_comp, data[0x32], data[0x33], data[0x34], data[0x35]);

      if (tcode_byte != 0 && tcode_byte == (guint8)(~tcode_comp))
        {
          guint16 tcode = ((tcode_byte >> 4) + 1) * 16 + 64;
          gint32 diff = (((tcode_byte & 0xf) + 2) * 100 * 256 / tcode) / 3 >> 4;
          guint16 fdt_delta = (diff << 8) | 0x80;
          fp_dbg ("  tcode=%d, diff=%d, fdt_delta=0x%04x", tcode, diff, fdt_delta);

          /* Patch config: reg 0x005c = tcode, reg 0x5882 = fdt_delta */
          for (int i = 0; i + 3 < 254; i += 4)
            {
              guint16 reg = (goodix_5e0a_config[i] << 8) | goodix_5e0a_config[i + 1];
              if (reg == 0x005c)
                { goodix_5e0a_config[i+2] = (tcode>>8)&0xFF; goodix_5e0a_config[i+3] = tcode&0xFF; }
              else if (reg == 0x5882)
                { goodix_5e0a_config[i+2] = (fdt_delta>>8)&0xFF; goodix_5e0a_config[i+3] = fdt_delta&0xFF; }
            }
          /* Recompute checksum */
          guint32 sum = 0;
          for (int i = 0; i < 254; i += 2)
            sum += (goodix_5e0a_config[i] << 8) | goodix_5e0a_config[i + 1];
          guint16 cksum = (guint16)(0 - sum);
          goodix_5e0a_config[254] = (cksum >> 8) & 0xFF;
          goodix_5e0a_config[255] = cksum & 0xFF;
          fp_dbg ("  Config patched, checksum=0x%02x%02x", goodix_5e0a_config[254], goodix_5e0a_config[255]);
        }
    }
  fpi_ssm_next_state (ssm);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_READ_AND_NOP1:
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, check_none_5e0a, ssm);
      break;

    case ACTIVATE_ENABLE_CHIP:
      goodix_send_enable_chip (dev, TRUE, check_none_5e0a, ssm);
      break;

    case ACTIVATE_NOP2:
      goodix_send_nop (dev, check_none_5e0a, ssm);
      break;

    case ACTIVATE_CHECK_FW_VERSION:
      fp_dbg ("GetFirmwareVersion (0xA8)...");
      goodix_send_query_firmware_version (dev, on_fw_version_5e0a, ssm);
      break;

    case ACTIVATE_RESET_SENSOR:
      if (self->in_iap_mode)
        {
          fp_dbg ("IAP mode — skipping ResetFingerPrint");
          fpi_ssm_next_state (ssm);
          break;
        }
      fp_dbg ("ResetFingerPrint (0xA2) [0x05, 0x14]...");
      {
        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (check_none_cmd_5e0a);
        cb_info->user_data = ssm;
        guint8 reset_payload[] = { 0x05, 0x14 };
        goodix_send_protocol (dev, 0xa2, reset_payload, sizeof (reset_payload),
                              NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case ACTIVATE_READ_OTP:
      if (self->in_iap_mode)
        {
          fp_dbg ("IAP mode — skipping OTP read");
          fpi_ssm_next_state (ssm);
          break;
        }
      fp_dbg ("GetOtp (0xA6)...");
      goodix_send_read_otp (dev, on_read_otp_5e0a, ssm);
      break;

    case ACTIVATE_CHECK_PSK:
      if (self->in_iap_mode)
        {
          /* In IAP mode, skip PSK read (unreliable) and go straight to enrollment */
          fp_info ("IAP mode — starting PSK enrollment directly");
          start_psk_enrollment (dev, ssm);
          break;
        }
      {
        /* 5e0a needs the full 16-byte payload: [length:4][offset:4][flags:4][zero:4] */
        guint8 psk_read_payload[16];
        guint32 len_le = GUINT32_TO_LE (32);
        guint32 off_le = GUINT32_TO_LE (0);
        guint32 flags_le = GUINT32_TO_LE (GOODIX_5E0A_PSK_FLAGS);
        guint32 zero = 0;
        memcpy (psk_read_payload + 0,  &len_le,   4);
        memcpy (psk_read_payload + 4,  &off_le,   4);
        memcpy (psk_read_payload + 8,  &flags_le, 4);
        memcpy (psk_read_payload + 12, &zero,     4);

        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (on_psk_read_5e0a);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, GOODIX_CMD_PRESET_PSK_READ,
                              psk_read_payload, sizeof (psk_read_payload),
                              NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                              goodix_receive_preset_psk_read, cb_info);
      }
      break;

    case ACTIVATE_UPLOAD_CONFIG:
      if (self->in_iap_mode)
        {
          fp_dbg ("IAP mode — skipping config upload");
          fpi_ssm_next_state (ssm);
          break;
        }
      fp_dbg ("DownloadChipConfig (0x90) 256 bytes...");
      {
        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (check_none_cmd_5e0a);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, 0x90, goodix_5e0a_config,
                              sizeof (goodix_5e0a_config), NULL, TRUE,
                              GOODIX_TIMEOUT, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case ACTIVATE_CMD_TLS:
      if (self->in_iap_mode)
        {
          fp_dbg ("IAP mode — skipping command TLS");
          fpi_ssm_next_state (ssm);
          break;
        }
      if (self->has_image_psk)
        {
          fp_dbg ("Command TLS with device PSK...");
          goodix_tls_init_with_psk (dev, self->image_psk, 32,
                                    on_cmd_tls_complete, ssm);
        }
      else
        {
          fp_warn ("No PSK — skipping command TLS");
          fpi_ssm_next_state (ssm);
        }
      break;

    case ACTIVATE_POV_IMAGE_CHECK:
      if (self->in_iap_mode)
        {
          fp_dbg ("IAP mode — skipping POV image check");
          fpi_ssm_next_state (ssm);
          break;
        }
      goodix_send_pov_image_check (dev, on_pov_image_check_done, ssm);
      break;

    case ACTIVATE_IMG_TLS:
      if (self->in_iap_mode)
        {
          fp_dbg ("IAP mode — skipping image TLS");
          fpi_ssm_next_state (ssm);
          break;
        }
      {
        const guint8 *psk = self->image_psk;
        guint psk_len = 32;
        if (!self->has_image_psk)
          fp_warn ("No image PSK — image TLS will likely fail");
        goodix_tls_init_image (dev, psk, psk_len, on_img_tls_complete, ssm);
      }
      break;

    case ACTIVATE_DONE:
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  G_DEBUG_HERE ();
  if (error)
    {
      fp_err ("Failed during 5e0a activation: %s (code: %d)",
              error->message, error->code);
    }
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
}

// ---- SCAN STATE MACHINE ----

enum scan_5e0a_states {
  SCAN_QUERY_MCU,
  SCAN_READ_FDT_BASE,
  SCAN_FDT_DOWN,
  SCAN_GET_IMAGE,
  SCAN_FDT_UP,
  SCAN_DONE,

  SCAN_5E0A_NUM_STATES,
};

static void
scan_on_read_img_5e0a (FpDevice *dev, guint8 *data, guint16 len,
                       gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);

  fp_dbg ("Got decrypted image data: %d bytes", len);

  // The decrypted data is the raw frame (10560 bytes) followed by a
  // 4-byte footer/checksum. Use only the first RAW_FRAME_SIZE bytes.
  if (len < GOODIX_5E0A_RAW_FRAME_SIZE)
    fp_warn ("Image data too small: %d < %d", len, GOODIX_5E0A_RAW_FRAME_SIZE);

  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  Goodix5e0aPix *raw_frame = calloc (GOODIX_5E0A_FRAME_SIZE,
                                     sizeof (Goodix5e0aPix));
  goodix_5e0a_decode_frame (raw_frame, GOODIX_5E0A_RAW_FRAME_SIZE, data);

  // Apply calibration: biased subtraction (same formula as 511 driver)
  if (self->calibration_img)
    {
      for (int i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
        {
          guint16 max = 0xFFFF;
          gint32 val = max - ((max - raw_frame[i]) - (max - self->calibration_img[i]));
          raw_frame[i] = (Goodix5e0aPix) CLAMP (val, 0, max);
        }
    }

  guint8 *squashed = calloc (GOODIX_5E0A_FRAME_SIZE, 1);
  goodix_5e0a_squash_frame (raw_frame, squashed, GOODIX_5E0A_FRAME_SIZE);
  free (raw_frame);

  // The sensor frame is GOODIX_5E0A_WIDTH (80) columns x GOODIX_5E0A_HEIGHT
  // (88) rows. The scan line width is 80 pixels, with 88 rows.
  int img_w = GOODIX_5E0A_WIDTH;   // 80
  int img_h = GOODIX_5E0A_HEIGHT;  // 88

  // Apply unsharp mask to enhance ridge/valley contrast.
  // The sensor produces low-contrast images; NBIS needs good ridge definition
  // to detect minutiae. Empirically, radius=3, strength=4.0 yields the most
  // minutiae (8 vs 3 without sharpening on test images).
  guint8 *sharpened = calloc (GOODIX_5E0A_FRAME_SIZE, 1);
  goodix_5e0a_unsharp_mask (sharpened, squashed, img_w, img_h, 3, 4.0);

  // Create the FpImage with the correct orientation.
  // Do NOT invert colors (empirically reduces minutiae to 0).
  // Do NOT fill dead zone with average (reduces minutiae to 0).
  // Keep 0xFF dead zone — NBIS handles white background well.
  FpImage *img = fp_image_new (img_w, img_h);
  img->ppmm = 19.685;  // 500 DPI
  // FPI_IMAGE_PARTIAL is critical for small sensors:
  // 1. Enables remove_perimeter_pts in NBIS — removes false minutiae at
  //    image borders that would otherwise poison matching.
  // 2. Signals to the matching pipeline that this is a partial impression,
  //    so border artifacts should be discounted.
  img->flags |= FPI_IMAGE_PARTIAL;
  memcpy (img->data, sharpened, GOODIX_5E0A_FRAME_SIZE);

  free (squashed);
  free (sharpened);

  // Upscale 2x — critical for small sensors. Makes the image large enough
  // for NBIS to reliably detect minutiae. Used by aes3k, egis0570, elanspi.
  FpImage *resized = fpi_image_resize (img, 2, 2);
  g_object_unref (img);

  // Enrollment diversity check — compare DECODED pixels, not raw TLS data.
  // Raw TLS data is always different (different encryption nonces), so we
  // must compare the squashed pixel data after image processing.
  guint16 img_size = resized->width * resized->height;
  if (self->prev_scan_data && self->prev_scan_size == img_size)
    {
      int same = 0;
      for (guint16 i = 0; i < img_size; i++)
        if (abs ((int)resized->data[i] - (int)self->prev_scan_data[i]) < 10)
          same++;
      int pct = same * 100 / img_size;
      fp_dbg ("Diversity check: %d%% similar to previous scan", pct);
      if (pct > 90)
        {
          fp_dbg ("Scan too similar (%d%%), rejecting — lift and reposition finger", pct);
          g_object_unref (resized);
          // Go to FDT_UP first so user must lift finger before retrying
          fpi_ssm_jump_to_state (ssm, SCAN_FDT_UP);
          return;
        }
    }
  // Save decoded pixels for next comparison
  g_free (self->prev_scan_data);
  self->prev_scan_data = g_memdup2 (resized->data, img_size);
  self->prev_scan_size = img_size;

  fpi_image_device_image_captured (img_dev, resized);
  fpi_ssm_next_state (ssm);
}

static void
on_query_mcu_ack_5e0a (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_warn ("query_mcu_state ACK error (non-fatal): %s", error->message);
      g_error_free (error);
    }
  fpi_ssm_next_state (ssm);
}

// DAC base values from OTP (used in FDT payloads)
static const guint8 dac_base[] = {
  0xa6, 0x00, 0xa7, 0x00, 0xa6, 0x00, 0xa7, 0x00
};

// FDT_MANUAL payload to read current sensor baseline
static const guint8 fdt_manual_payload[] = {
  0x0D, 0x01,
  0xa6, 0x00, 0xa7, 0x00, 0xa6, 0x00, 0xa7, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static void
build_fdt_payload (guint8 *payload, guint8 prefix, const guint16 *thresholds)
{
  payload[0] = prefix;
  payload[1] = 0x01;  // has_base flag
  // bytes [2..9]: DAC base from OTP
  memcpy (payload + 2, dac_base, 8);
  // bytes [10..21]: 6 threshold words (LE)
  for (int i = 0; i < 6; i++)
    {
      payload[10 + i * 2]     = thresholds[i] & 0xFF;
      payload[10 + i * 2 + 1] = (thresholds[i] >> 8) & 0xFF;
    }
  // bytes [22..25]: padding
  memset (payload + 22, 0, 4);
  // bytes [26..33]: DAC base copy
  memcpy (payload + 26, dac_base, 8);
  // byte [34]: trailing zero
  payload[34] = 0x00;
}

/* Set FDT payloads with has_base=0 (no thresholds, sensor uses internal defaults) */
static void
set_fdt_fallback_payloads (FpiDeviceGoodixTls5e0a *self)
{
  memset (self->fdt_down_payload, 0, sizeof (self->fdt_down_payload));
  self->fdt_down_payload[0] = 0x1c;
  self->fdt_down_payload[1] = 0x00;
  memcpy (self->fdt_down_payload + 2, dac_base, 8);
  memset (self->fdt_up_payload, 0, sizeof (self->fdt_up_payload));
  self->fdt_up_payload[0] = 0x0e;
  self->fdt_up_payload[1] = 0x00;
  memcpy (self->fdt_up_payload + 2, dac_base, 8);
}

static void
on_fdt_manual_response (FpDevice *dev, guint8 *data, guint16 length,
                        gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_warn ("FDT_MANUAL failed: %s — using has_base=0", error->message);
      g_error_free (error);
      set_fdt_fallback_payloads (FPI_DEVICE_GOODIXTLS5E0A (dev));
      fpi_ssm_next_state (ssm);
      return;
    }

  if (length < 16)
    {
      fp_warn ("FDT_MANUAL response too short (%d bytes) — using has_base=0",
               length);
      set_fdt_fallback_payloads (FPI_DEVICE_GOODIXTLS5E0A (dev));
      fpi_ssm_next_state (ssm);
      return;
    }

  // Parse the 6 raw base values from bytes [4..15]
  guint16 raw_base[6];
  for (int i = 0; i < 6; i++)
    raw_base[i] = data[4 + i * 2] | (data[4 + i * 2 + 1] << 8);

  // Compute thresholds: threshold[i] = ((raw_base[i] >> 1) << 8) | 0x80
  guint16 thresholds[6];
  fp_dbg ("FDT base readings:");
  for (int i = 0; i < 6; i++)
    {
      thresholds[i] = ((raw_base[i] >> 1) << 8) | 0x80;
      fp_dbg ("  zone %d: raw=0x%04x threshold=0x%04x", i, raw_base[i], thresholds[i]);
    }

  // Build dynamic FDT_DOWN and FDT_UP payloads
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  build_fdt_payload (self->fdt_down_payload, 0x1c, thresholds);
  build_fdt_payload (self->fdt_up_payload, 0x0e, thresholds);

  fp_dbg ("Built dynamic FDT payloads from sensor baseline");
  fpi_ssm_next_state (ssm);
}

static void
scan_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_QUERY_MCU:
      {
        // 5e0a: send query_mcu_state with reply=FALSE (fire-and-forget).
        // The Python driver sends b"\x00\x01\x00" but the device only
        // needs the ACK, not a data reply.
        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (on_query_mcu_ack_5e0a);
        cb_info->user_data = ssm;
        guint8 payload[] = { 0x55 };
        goodix_send_protocol (dev, GOODIX_CMD_QUERY_MCU_STATE, payload,
                              sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT,
                              FALSE, goodix_receive_none, cb_info);
      }
      break;

    case SCAN_READ_FDT_BASE:
      fp_dbg ("Reading FDT baseline (FDT_MANUAL cmd 0x36)...");
      {
        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (on_fdt_manual_response);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE,
                                  fdt_manual_payload,
                                  sizeof (fdt_manual_payload),
                                  NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                                  goodix_receive_default, cb_info);
      }
      break;

    case SCAN_FDT_DOWN:
      fp_dbg ("Waiting for finger (FDT_DOWN) with dynamic thresholds...");
      {
        FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (check_none_cmd_5e0a);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN,
                                  self->fdt_down_payload,
                                  sizeof (self->fdt_down_payload),
                                  NULL, TRUE, 0, TRUE,
                                  goodix_receive_default, cb_info);
      }
      break;

    case SCAN_GET_IMAGE:
      fpi_image_device_report_finger_status (img_dev, TRUE);
      goodix_tls_read_image_5e0a_with_payload (
        dev,
        goodix_5e0a_get_image_payload,
        sizeof (goodix_5e0a_get_image_payload),
        scan_on_read_img_5e0a, ssm);
      break;

    case SCAN_FDT_UP:
      // Wait for finger lift using FDT_UP (0x34) with dynamic thresholds.
      // The device responds when the finger is lifted (interrupt=0x200).
      fp_dbg ("Waiting for finger lift (FDT_UP cmd 0x34) with dynamic thresholds...");
      {
        FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
        GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));
        cb_info->callback = G_CALLBACK (check_none_cmd_5e0a);
        cb_info->user_data = ssm;
        goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP,
                                  self->fdt_up_payload,
                                  sizeof (self->fdt_up_payload),
                                  NULL, TRUE, 0, TRUE,
                              goodix_receive_default, cb_info);
      }
      break;

    case SCAN_DONE:
      fpi_image_device_report_finger_status (img_dev, FALSE);
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
scan_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      fp_err ("Failed to scan: %s (code: %d)", error->message, error->code);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  fp_dbg ("5e0a scan finished");
}

// ---- DEVICE CALLBACKS ----

static void
dev_activate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);

  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state,
                               ACTIVATE_5E0A_NUM_STATES),
                 activate_complete);
}

static void
dev_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    {
      fpi_ssm_start (fpi_ssm_new (FP_DEVICE (img_dev), scan_run_state,
                                   SCAN_5E0A_NUM_STATES),
                     scan_complete);
    }
}

static void
dev_deactivate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);

  goodix_reset_state (dev);

  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  g_clear_pointer (&self->calibration_img, free);
  g_clear_pointer (&self->prev_scan_data, g_free);
  self->prev_scan_size = 0;

  GError *error = NULL;
  goodix_shutdown_tls (dev, &error);
  goodix_shutdown_image_tls (dev, &error);

  fpi_image_device_deactivate_complete (img_dev, error);
}

static void
dev_init (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  GError *error = NULL;

  if (goodix_dev_init (dev, &error))
    {
      fpi_image_device_open_complete (img_dev, error);
      return;
    }

  fpi_image_device_open_complete (img_dev, NULL);
}

static void
dev_deinit (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  GError *error = NULL;

  if (goodix_dev_deinit (dev, &error))
    {
      fpi_image_device_close_complete (img_dev, error);
      return;
    }

  fpi_image_device_close_complete (img_dev, NULL);
}

// ---- TYPE INIT ----

static gboolean
load_psk_from_file (FpiDeviceGoodixTls5e0a *self)
{
  // Try multiple config file locations
  const char *paths[] = {
    "/var/lib/fprint/goodix-5e0a.psk",
    NULL,   // filled with $HOME path below
  };

  // Build home-based path
  const char *home = g_get_home_dir ();
  g_autofree char *home_path = NULL;
  if (home)
    {
      home_path = g_strdup_printf ("%s/.config/libfprint/goodix-5e0a.psk", home);
      paths[1] = home_path;
    }

  for (int i = 0; i < 2; i++)
    {
      if (!paths[i])
        continue;

      g_autofree char *contents = NULL;
      gsize len = 0;

      if (!g_file_get_contents (paths[i], &contents, &len, NULL))
        continue;

      // Strip whitespace/newlines
      g_strstrip (contents);
      gsize hex_len = strlen (contents);

      if (hex_len < 64)
        {
          fp_warn ("PSK file %s too short (%zu chars, need 64 hex)", paths[i], hex_len);
          continue;
        }

      // Parse hex string to bytes
      gboolean valid = TRUE;
      for (int j = 0; j < 32 && valid; j++)
        {
          char byte_str[3] = { contents[j*2], contents[j*2+1], 0 };
          char *endp;
          unsigned long val = strtoul (byte_str, &endp, 16);
          if (*endp != 0)
            {
              valid = FALSE;
              break;
            }
          self->image_psk[j] = (guint8) val;
        }

      if (valid)
        {
          fp_info ("Loaded image PSK from %s", paths[i]);
          self->has_image_psk = TRUE;
          return TRUE;
        }
      else
        {
          fp_warn ("Invalid hex in PSK file %s", paths[i]);
        }
    }

  return FALSE;
}

static void
fpi_device_goodixtls5e0a_init (FpiDeviceGoodixTls5e0a *self)
{
  memset (self->image_psk, 0, sizeof (self->image_psk));
  self->has_image_psk = FALSE;

  // Load device-specific PSK from config file.
  // The PSK is unique per device, extracted via extract_psk.py.
  // Store it as 64 hex chars in one of:
  //   /var/lib/fprint/goodix-5e0a.psk
  //   ~/.config/libfprint/goodix-5e0a.psk
  if (!load_psk_from_file (self))
    fp_warn ("No image PSK loaded — image TLS will fail. "
             "Run extract_psk.py and save PSK to "
             "/var/lib/fprint/goodix-5e0a.psk");
}

static void
fpi_device_goodixtls5e0a_class_init (FpiDeviceGoodixTls5e0aClass *class)
{
  FpiDeviceGoodixTlsClass *gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (class);
  FpImageDeviceClass *img_dev_class = FP_IMAGE_DEVICE_CLASS (class);

  gx_class->interface = GOODIX_5E0A_INTERFACE;
  gx_class->ep_in = GOODIX_5E0A_EP_IN;
  gx_class->ep_out = GOODIX_5E0A_EP_OUT;

  dev_class->id = "goodixtls5e0a";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 5e0a";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = goodix_5e0a_id_table;
  // 8 enrollment stages: enough captures for bozorth3 to build a reliable
  // template from a small sensor, without exhausting user patience.
  // Each stage captures one image; the NBIS matcher compares against all
  // stored prints in the template, so more stages = more reference angles.
  dev_class->nr_enroll_stages = 20;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  // bz3_threshold: match score threshold for bozorth3 matcher.
  // Small sensors (80x88) produce few minutiae (typically 5-12), so the
  // match scores are inherently lower than full-size sensors.
  // Default libfprint value is 40; we use 20 to balance security vs usability.
  // Too high (>25) = constant false rejections with so few minutiae.
  // Too low (<12) = potential false accepts.
  img_dev_class->bz3_threshold = 20;
  img_dev_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  // Sensor frame: 80 pixels wide, 88 pixels tall
  img_dev_class->img_width = GOODIX_5E0A_WIDTH;    // 80
  img_dev_class->img_height = GOODIX_5E0A_HEIGHT;  // 88

  img_dev_class->activate = dev_activate;
  img_dev_class->change_state = dev_change_state;
  img_dev_class->deactivate = dev_deactivate;
  img_dev_class->img_open = dev_init;
  img_dev_class->img_close = dev_deinit;

  fpi_device_class_auto_initialize_features (dev_class);
}
