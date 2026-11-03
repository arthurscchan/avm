/*
 * Copyright (c) 2026, Alliance for Open Media. All rights reserved
 *
 * This source code is subject to the terms of the BSD 3-Clause Clear License
 * and the Alliance for Open Media Patent License 1.0. If the BSD 3-Clause Clear
 * License was not distributed with this source code, you can obtain it at
 * aomedia.org/license/patent-license/.
 */

/*
 * Fuzzing rationale (avm-enc-fuzzer pair):
 *
 * The avm OSS-Fuzz integration builds with CONFIG_AV2_ENCODER=0, so the
 * encoder module (~172k lines under av2/encoder, the largest body of code in
 * the project) is compiled out of the fuzzed library entirely and never
 * appears in any coverage report. This harness is the encode-side
 * complement: a fuzz-driven encoder option matrix using the same public API
 * sequence as the project's own examples (simple_encoder.c).
 *
 * Threat model: encoder input is an uncompressed frame plus a configuration,
 * produced by applications; encoders routinely ingest attacker-influenced
 * pixels in transcoding pipelines, and every memory-safety defect reached
 * from this documented public API with in-range configuration values is a
 * real bug. Invalid configurations are constructed only within documented
 * valid ranges (even dimensions 16..128, cpu_used 5..9 to bound runtime,
 * small frame counts, bounded rate-control values) so that crashes or
 * sanitizer reports are attributable to the codec, not to the harness.
 *
 * What is fuzzed: encoder configuration (dimensions, threads, lag, error
 * resiliency, rate-control mode VBR/CBR/CQ/Q, target bitrate, quantizer
 * bounds), a matrix of encoder controls, pseudo-random plane content,
 * frame flags (forced keyframes, per-reference NO_REF bits, NO_UPD_ALL),
 * packet draining, and the flush-to-EOF loop.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "avm/avm_encoder.h"
#include "avm/avmcx.h"  // avm_codec_av2_cx(), AVME_*/AV2E_* controls, EFLAGs.

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

#define MAX_ENCODE_FRAMES 8
#define MAX_FLUSH_ROUNDS 16
// Odd value marks "control not applied" for optional controls.
#define CTRL_SKIP 0xFF

namespace {

struct Prng {
  uint32_t state;
  explicit Prng(uint32_t seed) : state(seed ? seed : 0x9E3779B9u) {}
  uint32_t next() {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
  }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 16) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  // Configuration: bounded so encoder runtime stays small even at cpu_used 5.
  const unsigned int width = 16 + 2 * fdp.ConsumeIntegralInRange<uint8_t>(0, 56);
  const unsigned int height =
      16 + 2 * fdp.ConsumeIntegralInRange<uint8_t>(0, 56);
  const int frames =
      1 + fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_ENCODE_FRAMES - 1);
  const int cpu_used = fdp.ConsumeIntegralInRange<uint8_t>(5, 9);
  const int keyint = fdp.ConsumeIntegralInRange<uint8_t>(1, 16);
  const int threads = 1 + fdp.ConsumeIntegralInRange<uint8_t>(0, 1);
  const int lag = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
  const int end_usage = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
  const int bitrate = 40 + fdp.ConsumeIntegralInRange<uint8_t>(0, 200);
  const int qmin = fdp.ConsumeIntegralInRange<uint8_t>(0, 40);
  const int qmax = 120 + fdp.ConsumeIntegralInRange<uint8_t>(0, 75);
  const int error_resilient = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);
  const uint32_t content_seed = fdp.ConsumeIntegral<uint32_t>();

  avm_codec_iface_t *encoder = avm_codec_av2_cx();
  if (!encoder) {
    return 0;
  }

  avm_codec_enc_cfg_t cfg;
  if (avm_codec_enc_config_default(encoder, &cfg, 0) != AVM_CODEC_OK) {
    return 0;
  }
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 30;
  cfg.rc_target_bitrate = (unsigned int)bitrate;
  cfg.g_threads = (unsigned int)threads;
  cfg.g_lag_in_frames = (unsigned int)lag;
  cfg.g_error_resilient = (avm_codec_er_flags_t)error_resilient;
  cfg.g_limit = (unsigned int)frames;
  cfg.rc_end_usage = (enum avm_rc_mode)end_usage;
  cfg.rc_min_quantizer = (unsigned int)qmin;
  cfg.rc_max_quantizer = (unsigned int)qmax;
  cfg.g_profile = 0;

  avm_codec_ctx_t codec;
  if (avm_codec_enc_init(&codec, encoder, &cfg, 0) != AVM_CODEC_OK) {
    return 0;
  }

  static_cast<void>(avm_codec_control(&codec, AVME_SET_CPUUSED, cpu_used));

  // Optional controls: applied only when the fuzz byte is in range, so the
  // default path is exercised as well as every knob.
  const uint8_t auto_altref = fdp.ConsumeIntegral<uint8_t>();
  if (auto_altref != CTRL_SKIP) {
    static_cast<void>(
        avm_codec_control(&codec, AVME_SET_ENABLEAUTOALTREF, auto_altref & 1));
  }
  const uint8_t arnr_frames = fdp.ConsumeIntegral<uint8_t>();
  if (arnr_frames != CTRL_SKIP && arnr_frames <= 15) {
    static_cast<void>(
        avm_codec_control(&codec, AVME_SET_ARNR_MAXFRAMES, arnr_frames));
  }
  const uint8_t arnr_strength = fdp.ConsumeIntegral<uint8_t>();
  if (arnr_strength != CTRL_SKIP && arnr_strength <= 6) {
    static_cast<void>(
        avm_codec_control(&codec, AVME_SET_ARNR_STRENGTH, arnr_strength));
  }
  const uint8_t sharpness = fdp.ConsumeIntegral<uint8_t>();
  if (sharpness != CTRL_SKIP && sharpness <= 7) {
    static_cast<void>(avm_codec_control(&codec, AVME_SET_SHARPNESS, sharpness));
  }
  const uint8_t static_thr = fdp.ConsumeIntegral<uint8_t>();
  if (static_thr != CTRL_SKIP) {
    static_cast<void>(
        avm_codec_control(&codec, AVME_SET_STATIC_THRESHOLD, static_thr));
  }
  const uint8_t tuning = fdp.ConsumeIntegral<uint8_t>();
  if (tuning != CTRL_SKIP && tuning <= 4) {
    static_cast<void>(avm_codec_control(&codec, AVME_SET_TUNING, tuning));
  }
  const uint8_t qp = fdp.ConsumeIntegral<uint8_t>();
  if (qp != CTRL_SKIP) {
    static_cast<void>(avm_codec_control(&codec, AVME_SET_QP, qp));
  }
  const uint8_t intra_pct = fdp.ConsumeIntegral<uint8_t>();
  if (intra_pct != CTRL_SKIP) {
    static_cast<void>(
        avm_codec_control(&codec, AVME_SET_MAX_INTRA_BITRATE_PCT, intra_pct));
  }

  const uint8_t mlayers = fdp.ConsumeIntegral<uint8_t>();
  if (mlayers != CTRL_SKIP && mlayers >= 1 && mlayers <= 8) {
    static_cast<void>(
        avm_codec_control(&codec, AVME_SET_NUMBER_MLAYERS, mlayers));
  }
  const uint8_t mlayer_id = fdp.ConsumeIntegral<uint8_t>();
  if (mlayer_id != CTRL_SKIP && mlayer_id <= 7) {
    static_cast<void>(avm_codec_control(&codec, AVME_SET_MLAYER_ID, mlayer_id));
  }
  const uint8_t tile_cols = fdp.ConsumeIntegral<uint8_t>();
  if (tile_cols != CTRL_SKIP && tile_cols <= 6) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_TILE_COLUMNS, tile_cols));
  }
  const uint8_t tile_rows = fdp.ConsumeIntegral<uint8_t>();
  if (tile_rows != CTRL_SKIP && tile_rows <= 6) {
    static_cast<void>(avm_codec_control(&codec, AV2E_SET_TILE_ROWS, tile_rows));
  }
  const uint8_t tpl = fdp.ConsumeIntegral<uint8_t>();
  if (tpl != CTRL_SKIP) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_ENABLE_TPL_MODEL, tpl & 1));
  }
  const uint8_t kf_filter = fdp.ConsumeIntegral<uint8_t>();
  if (kf_filter != CTRL_SKIP) {
    static_cast<void>(avm_codec_control(&codec,
                                        AV2E_SET_ENABLE_KEYFRAME_FILTERING,
                                        kf_filter & 1));
  }
  const uint8_t sframe = fdp.ConsumeIntegral<uint8_t>();
  if (sframe != CTRL_SKIP && sframe <= 2) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_ENABLE_SFRAME, sframe));
  }
  const uint8_t aq_mode = fdp.ConsumeIntegral<uint8_t>();
  if (aq_mode != CTRL_SKIP && aq_mode <= 3) {
    static_cast<void>(avm_codec_control(&codec, AV2E_SET_AQ_MODE, aq_mode));
  }
  const uint8_t boost = fdp.ConsumeIntegral<uint8_t>();
  if (boost != CTRL_SKIP && boost <= 100) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_FRAME_PERIODIC_BOOST, boost));
  }
  const uint8_t noise = fdp.ConsumeIntegral<uint8_t>();
  if (noise != CTRL_SKIP && noise <= 4) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_NOISE_SENSITIVITY, noise));
  }
  const uint8_t tune_content = fdp.ConsumeIntegral<uint8_t>();
  if (tune_content != CTRL_SKIP && tune_content <= 2) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_TUNE_CONTENT, tune_content));
  }
  const uint8_t cdf_mode = fdp.ConsumeIntegral<uint8_t>();
  if (cdf_mode != CTRL_SKIP && cdf_mode <= 4) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_CDF_UPDATE_MODE, cdf_mode));
  }
  const uint8_t gf_min = fdp.ConsumeIntegral<uint8_t>();
  if (gf_min != CTRL_SKIP && gf_min >= 1) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_MIN_GF_INTERVAL, gf_min));
  }
  const uint8_t gf_max = fdp.ConsumeIntegral<uint8_t>();
  if (gf_max != CTRL_SKIP && gf_max >= 2) {
    static_cast<void>(
        avm_codec_control(&codec, AV2E_SET_MAX_GF_INTERVAL, gf_max));
  }

  avm_image_t raw;
  memset(&raw, 0, sizeof(raw));
  if (!avm_img_alloc(&raw, AVM_IMG_FMT_I420, width, height, 1)) {
    avm_codec_destroy(&codec);
    return 0;
  }

  Prng prng(content_seed);
  const unsigned int y_size = width * height;
  const unsigned int uv_size = ((width + 1) / 2) * ((height + 1) / 2);
  for (unsigned int i = 0; i < y_size; ++i) {
    raw.planes[AVM_PLANE_Y][i] = (uint8_t)prng.next();
  }
  for (unsigned int i = 0; i < uv_size; ++i) {
    raw.planes[AVM_PLANE_U][i] = (uint8_t)(prng.next() >> 8);
    raw.planes[AVM_PLANE_V][i] = (uint8_t)(prng.next() >> 16);
  }

  for (int frame = 0; frame < frames; ++frame) {
    int flags = 0;
    if (frame % keyint == 0) flags |= AVM_EFLAG_FORCE_KF;
    // Per-reference NO_REF / NO_UPD bits driven by the content seed: valid
    // API usage that steers reference buffering and update decisions.
    if (prng.next() & 1) flags |= AVM_EFLAG_NO_REF_LAST;
    if (prng.next() & 1) flags |= AVM_EFLAG_NO_REF_GF;
    if (prng.next() & 1) flags |= AVM_EFLAG_NO_REF_ARF;
    if (prng.next() & 1) flags |= AVM_EFLAG_NO_UPD_ALL;

    if (avm_codec_encode(&codec, &raw, frame, 1, flags) != AVM_CODEC_OK) {
      break;
    }
    avm_codec_iter_t iter = nullptr;
    const avm_codec_cx_pkt_t *pkt = nullptr;
    while ((pkt = avm_codec_get_cx_data(&codec, &iter)) != nullptr) {
      if (pkt->kind == AVM_CODEC_CX_FRAME_PKT && pkt->data.frame.sz > 0) {
        // Touch the packet payload bounds the way downstream consumers do.
        const uint8_t *frame_bytes =
            static_cast<const uint8_t *>(pkt->data.frame.buf);
        volatile uint8_t first = frame_bytes[0];
        volatile uint8_t last = frame_bytes[pkt->data.frame.sz - 1];
        static_cast<void>(first);
        static_cast<void>(last);
        static_cast<void>(pkt->data.frame.flags & AVM_FRAME_IS_KEY);
      }
    }
  }

  // Flush: null-frame encode until the encoder stops producing packets.
  for (int i = 0; i < MAX_FLUSH_ROUNDS; ++i) {
    if (avm_codec_encode(&codec, nullptr, frames + i, 1, 0) != AVM_CODEC_OK) {
      break;
    }
    int got_packets = 0;
    avm_codec_iter_t iter = nullptr;
    const avm_codec_cx_pkt_t *pkt = nullptr;
    while ((pkt = avm_codec_get_cx_data(&codec, &iter)) != nullptr) {
      got_packets = 1;
    }
    if (!got_packets) break;
  }

  int last_quantizer = 0;
  static_cast<void>(
      avm_codec_control(&codec, AVME_GET_LAST_QUANTIZER, &last_quantizer));

  avm_img_free(&raw);
  avm_codec_destroy(&codec);
  return 0;
}