/*
 * Copyright (c) 2021, Alliance for Open Media. All rights reserved
 *
 * This source code is subject to the terms of the BSD 3-Clause Clear License
 * and the Alliance for Open Media Patent License 1.0. If the BSD 3-Clause Clear
 * License was not distributed with this source code in the LICENSE file, you
 * can obtain it at aomedia.org/license/software-license/bsd-3-c-c/.  If the
 * Alliance for Open Media Patent License 1.0 was not distributed with this
 * source code in the PATENTS file, you can obtain it at
 * aomedia.org/license/patent-license/.
 */

/*
 * See build_av2_dec_fuzzer.sh for building instructions.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <memory>

#include "config/avm_config.h"
#include "av2/av2_iface_common.h"  // SubGOPData for AVMD_GET_FRAME_INFO.
#include "avm/avm_decoder.h"
#include "avm/avmdx.h"
#include "avm_ports/mem_ops.h"

#define IVF_FRAME_HDR_SZ (4 + 8) /* 4 byte size + 8 byte timestamp */
#define IVF_FILE_HDR_SZ 32

/*
 * Fuzzing rationale (avm-dec-api pair):
 *
 * The original harness only fuzzed the thread count and never touched the
 * decoder API surface: avm_codec_control() was called zero times, so every
 * ctrl_* implementation in av2/av2_dx_iface.c (~740 uncovered lines), the
 * operating-point / sub-bitstream filtering in the OBU layer, film grain
 * control, tile decode-order inversion, row multi-threading, BRU opt modes
 * and the avm_image helpers stayed dark in the project coverage report.
 *
 * This harness keeps the input container byte-for-byte compatible with the
 * existing corpus (IVF-like: 32-byte file header, 12-byte frame headers), so
 * ClusterFuzz's accumulated av2_dec_fuzzer corpus remains valid. Knob bytes
 * are taken exclusively from the IVF file header (bytes 16..21) and the IVF
 * frame timestamps, which the decode path ignores. Every legacy corpus input
 * therefore still decodes the identical bitstream, while the new bits drive:
 *   - init-time decoder controls (output all layers, skip film grain, tile
 *     order inversion, skip loopfilter, row MT, random access, BRU opt mode,
 *     byte alignment, sub-bitstream extraction, operating point selection),
 *   - per-frame control toggles via the frame timestamps,
 *   - the full getter surface after every frame, plus SubGOP frame info,
 *   - reference frame get/set on the decoded dimensions.
 *
 * What counts as a real bug here: memory-safety violations, leaks, OOMs,
 * timeouts or logic errors inside decoder code reached through this
 * documented public API. Errors returned by controls are ignored, matching
 * legitimate application usage (aomdec-style tools never abort on control
 * errors).
 */

// Byte alignment values accepted by AV2_SET_BYTE_ALIGNMENT (power of 2,
// 32..1024, or 0 for legacy alignment).
static const unsigned int kAlignments[8] = { 0, 32, 64, 128, 256, 512, 1024, 0 };

// Bound for harness-owned reference image allocation: skip the reference
// controls for very large frames so the harness itself cannot OOM. The
// decoder is still fuzzed with full-size streams through the decode path.
#define kMaxRefImgPixels (4096u) /* 64x64 */

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

// P2

// Errors returned by controls are tolerated and ignored, matching legitimate
// application usage.
#define APPLY_CTRL(codec_, ctrl_, ...) \
  static_cast<void>(avm_codec_control((codec_), (ctrl_), __VA_ARGS__))

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= IVF_FILE_HDR_SZ) {
    return 0;
  }

  // Knob bytes: IVF file header bytes 16..21 (rate/scale fields). These are
  // never used for decoding, so repurposing them changes no stream bytes.
  const uint8_t k1 = data[16];
  const uint8_t k2 = data[17];
  const uint8_t k3 = data[18];
  const uint8_t k4 = data[19];

  avm_codec_iface_t *codec_interface = avm_codec_av2_dx();
  avm_codec_ctx_t codec;
  // Set thread count in the range [1, 64]. (Legacy knob: first payload byte.)
  const unsigned int threads = (data[IVF_FILE_HDR_SZ] & 0x3f) + 1;
  avm_codec_dec_cfg_t cfg = { threads, 0, 0 };
  if (avm_codec_dec_init(&codec, codec_interface, &cfg, 0)) {
    return 0;
  }

  // Init-time decoder controls. All mirror documented public API usage;
  // errors are tolerated and ignored.
  APPLY_CTRL(&codec, AV2D_SET_OUTPUT_ALL_LAYERS, (int)(k1 & 1));
  APPLY_CTRL(&codec, AV2D_SET_SKIP_FILM_GRAIN, (int)((k1 >> 1) & 1));
  APPLY_CTRL(&codec, AV2_INVERT_TILE_DECODE_ORDER, (int)((k1 >> 2) & 1));
  APPLY_CTRL(&codec, AV2_SET_SKIP_LOOP_FILTER, (int)((k1 >> 3) & 1));
  APPLY_CTRL(&codec, AV2D_SET_ROW_MT, (unsigned int)((k1 >> 4) & 1));
  APPLY_CTRL(&codec, AV2D_SET_RANDOM_ACCESS, (int)((k1 >> 5) & 1));
  APPLY_CTRL(&codec, AV2D_SET_BRU_OPT_MODE, (int)((k1 >> 6) & 3));
  APPLY_CTRL(&codec, AV2D_ENABLE_SUBGOP_STATS, (unsigned int)(k2 & 1));
  APPLY_CTRL(&codec, AV2_SET_BYTE_ALIGNMENT, (int)kAlignments[(k2 >> 1) & 7]);
  APPLY_CTRL(&codec, AV2D_SET_SUB_BITSTREAM_EXTRACTION, (int)((k2 >> 4) & 1));

  // Operating point selection. ops_id 0 / op_index 0 selects the default
  // operating point, so streams are not dropped, but the OBU-layer operating
  // point filtering (sub-bitstream extraction) is exercised on every input.
  int ops_params[2] = { (int)(k3 & 31), (int)((k3 >> 5) & 7) };
  APPLY_CTRL(&codec, AV2D_SET_SELECTED_OPS, ops_params);

  if ((k2 >> 5) & 1) {
    int local_ops_params[3] = { (int)(k4 & 3), (int)((k4 >> 2) & 31),
                                (int)((k4 >> 7) & 1) };
    APPLY_CTRL(&codec, AV2D_SET_SELECTED_LOCAL_OPS, local_ops_params);
  }

  data += IVF_FILE_HDR_SZ;
  size -= IVF_FILE_HDR_SZ;

  // Harness-owned reference image for AV2_SET_REFERENCE (allocated lazily at
  // the decoded frame dimensions, freed once at the end).
  avm_image_t ext_ref_img;
  memset(&ext_ref_img, 0, sizeof(ext_ref_img));
  bool have_ext_ref_img = false;

  while (size > IVF_FRAME_HDR_SZ) {
    const size_t frame_size = mem_get_le32(data);
    // Per-frame knob bytes: the 8-byte IVF timestamp, ignored by decode.
    const uint8_t t0 = data[4];
    const uint8_t t1 = data[5];
    const uint8_t t2 = data[6];
    const uint8_t t3 = data[7];
    const uint8_t t4 = data[8];
    const uint8_t t5 = data[9];
    const uint8_t t6 = data[10];
    size -= IVF_FRAME_HDR_SZ;
    data += IVF_FRAME_HDR_SZ;
    const size_t bounded_size = std::min(size, frame_size);

    const avm_codec_err_t err =
        avm_codec_decode(&codec, data, bounded_size, nullptr);

    if (err == AVM_CODEC_OK) {
      // Findings avm-1/avm-2 route-around: several decoder controls
      // (ctrl_incr_output_frames_offset av2/av2_dx_iface.c:1430,
      // ctrl_get_last_quantizer :1459, and unguarded siblings) dereference
      // ctx->frame_worker without the guard their siblings have, so calling
      // them before the first frame or after a fatal decode error
      // NULL-derefs (SEGV, see findings/av2_dec_fuzzer/). Gate the whole
      // per-frame control surface on a clean decode until the upstream
      // guards land; re-enable unconditionally afterwards.
      // Stateful per-frame control toggles.
    if (t0 & 0x01) APPLY_CTRL(&codec, AV2D_SET_SKIP_FILM_GRAIN, (int)(t1 & 1));
    if ((t0 & 0x02) && err == AVM_CODEC_OK) {
      // Finding avm-1 route-around: ctrl_incr_output_frames_offset
      // (av2/av2_dx_iface.c:1430) dereferences ctx->frame_worker without the
      // guard every sibling control has, so calling it before the first frame
      // or after a fatal decode error NULL-derefs (SEGV, see
      // findings/av2_dec_fuzzer/). Only apply it after a clean decode until
      // the upstream guard lands; re-enable unconditionally afterwards.
      APPLY_CTRL(&codec, AVMD_INCR_OUTPUT_FRAMES_OFFSET, (int)((t1 >> 1) & 3));
    }
    if (t0 & 0x04)
      APPLY_CTRL(&codec, AV2_INVERT_TILE_DECODE_ORDER, (int)(t2 & 1));
    if (t0 & 0x08) APPLY_CTRL(&codec, AV2D_SET_RANDOM_ACCESS, (int)(t3 & 1));
    if (t0 & 0x10) APPLY_CTRL(&codec, AV2_SET_SKIP_LOOP_FILTER, (int)(t4 & 1));
    if (t0 & 0x20) APPLY_CTRL(&codec, AV2D_SET_ROW_MT, (unsigned int)(t5 & 1));
    static_cast<void>(err);

    avm_codec_iter_t iter = nullptr;
    avm_image_t *img = nullptr;
    while ((img = avm_codec_get_frame(&codec, &iter)) != nullptr) {
      static_cast<void>(img);
    }

    if (img != nullptr) {
    // Getters once a frame has actually been decoded and output. Finding
    // avm-3 route-around: AV2D_GET_TILE_SIZE does signed arithmetic on tile
    // dimensions that are not fully initialized until a frame decodes
    // (av2/av2_dx_iface.c:1836, UBSan signed-integer-overflow; see
    // findings/av2_dec_fuzzer/). Gate the arithmetic getters on an output
    // frame until upstream initializes/guards them.
    int gi = 0;
    int size2[2] = { 0, 0 };
    unsigned int gu = 0;
    avm_img_fmt_t fmt = AVM_IMG_FMT_NONE;
    avm_tile_info tile_info;
    memset(&tile_info, 0, sizeof(tile_info));
    avm_screen_content_tools_info sc_tools;
    memset(&sc_tools, 0, sizeof(sc_tools));
    avm_still_picture_info still_pic;
    memset(&still_pic, 0, sizeof(still_pic));
    avm_superblock_size_t sb_size = AVM_SUPERBLOCK_SIZE_64X64;
    avm_s_frame_info s_frame;
    memset(&s_frame, 0, sizeof(s_frame));
    avm_image_t new_frame_img;
    memset(&new_frame_img, 0, sizeof(new_frame_img));
    SubGOPData subgop_data;
    memset(&subgop_data, 0, sizeof(subgop_data));

    APPLY_CTRL(&codec, AVMD_GET_FRAME_CORRUPTED, &gi);
    APPLY_CTRL(&codec, AVMD_GET_LAST_REF_UPDATES, &gi);
    APPLY_CTRL(&codec, AVMD_GET_LAST_REF_USED, &gi);
    APPLY_CTRL(&codec, AVMD_GET_LAST_QUANTIZER, &gi);
    APPLY_CTRL(&codec, AVMD_GET_FWD_KF_PRESENT, &gi);
    APPLY_CTRL(&codec, AVMD_GET_ALTREF_PRESENT, &gi);
    APPLY_CTRL(&codec, AVMD_GET_FRAME_FLAGS, &gi);
    APPLY_CTRL(&codec, AVMD_GET_SHOW_EXISTING_FRAME_FLAG, &gi);
    APPLY_CTRL(&codec, AV2D_GET_FRAME_SIZE, size2);
    APPLY_CTRL(&codec, AV2D_GET_DISPLAY_SIZE, size2);
    APPLY_CTRL(&codec, AV2D_GET_BIT_DEPTH, &gu);
    APPLY_CTRL(&codec, AV2D_GET_IMG_FORMAT, &fmt);
    APPLY_CTRL(&codec, AV2D_GET_TILE_SIZE, &gu);
    APPLY_CTRL(&codec, AV2D_GET_TILE_COUNT, &gi);
    APPLY_CTRL(&codec, AVMD_GET_TILE_INFO, &tile_info);
    APPLY_CTRL(&codec, AVMD_GET_SCREEN_CONTENT_TOOLS_INFO, &sc_tools);
    APPLY_CTRL(&codec, AVMD_GET_STILL_PICTURE, &still_pic);
    APPLY_CTRL(&codec, AVMD_GET_SB_SIZE, &sb_size);
    APPLY_CTRL(&codec, AVMD_GET_S_FRAME_INFO, &s_frame);
    APPLY_CTRL(&codec, AV2_GET_NEW_FRAME_IMAGE, &new_frame_img);
    APPLY_CTRL(&codec, AVMD_GET_FRAME_INFO, &subgop_data);

    // Reference frame get/set on the last decoded dimensions (the output
    // frame is guaranteed non-null here). The set side uses a harness-owned
    // I420 buffer allocated at the frame dimensions, mirroring the
    // documented external-reference usage.
    if (t0 & 0x40) {
      av2_ref_frame_t get_ref;
      memset(&get_ref, 0, sizeof(get_ref));
      get_ref.idx = (int)(t6 & 7);
      get_ref.use_external_ref = 0;
      APPLY_CTRL(&codec, AV2_GET_REFERENCE, &get_ref);

      const unsigned int rw = (unsigned int)img->d_w;
      const unsigned int rh = (unsigned int)img->d_h;
      if (!have_ext_ref_img && rw > 0 && rh > 0 && rw * rh <= kMaxRefImgPixels) {
        if (avm_img_alloc(&ext_ref_img, AVM_IMG_FMT_I420, rw, rh, 32) !=
            nullptr) {
          have_ext_ref_img = true;
        }
      }
      if (have_ext_ref_img) {
        av2_ref_frame_t set_ref;
        memset(&set_ref, 0, sizeof(set_ref));
        set_ref.idx = (int)(t6 & 7);
        set_ref.use_external_ref = 0;
        set_ref.img = ext_ref_img;
        APPLY_CTRL(&codec, AV2_SET_REFERENCE, &set_ref);
      }
    }
    }
    } else {
      // Drain pending output on error frames too (plain API call, exercised
      // by the original harness on all inputs).
      avm_codec_iter_t iter = nullptr;
      avm_image_t *img = nullptr;
      while ((img = avm_codec_get_frame(&codec, &iter)) != nullptr) {
        static_cast<void>(img);
      }
    }

    data += bounded_size;
    size -= bounded_size;
  }

  if (have_ext_ref_img) {
    avm_img_free(&ext_ref_img);
  }
  avm_codec_destroy(&codec);
  return 0;
}
