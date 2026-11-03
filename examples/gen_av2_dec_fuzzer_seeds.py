#!/usr/bin/env python3
# Copyright (c) 2026, Alliance for Open Media. All rights reserved
#
# This source code is subject to the terms of the BSD 3-Clause Clear License
# and the Alliance for Open Media Patent License 1.0. If the BSD 3-Clause Clear
# License was not distributed with this source code, you can obtain it at
# aomedia.org/license/software-license/bsd-3-c-c/.  If the Alliance for Open
# Media Patent License 1.0 was not distributed with this source code, you can
# obtain it at aomedia.org/license/patent-license/.

"""Structured seed corpus generator for the av2_dec_fuzzer harness.

Emits IVF-wrapped streams made of byte-level OBU structures that the
accumulated production corpus rarely produces on its own: temporal
delimiters, padding, metadata carriers, multi-frame headers, tile
groups, switch/SEF/TIP OBUs, buffer removal timing, layer configuration
records, operating point sets, bridge frames, RAS frames, quantization
matrices, film grain models, content interpretation and reserved OBU
types.

AV2 OBU framing (av2/common/obu_util.c): the uleb128 size field comes
FIRST and includes the OBU header byte(s); the header byte is
extension_flag(1) | type(5) | tlayer_id(2), MSB first.

The seeds exercise the OBU dispatch and parse-entry/error paths; they do
not need to decode successfully to be useful. The IVF rate/scale fields
(bytes 16..19) are knob bytes for the decoder-API controls in the
extended harness, and the IVF frame timestamps drive per-frame control
toggles, so the seeds also seed the control combinations.

Usage: gen_av2_dec_fuzzer_seeds.py <output-directory>
"""

import os
import struct
import sys

# OBU types (avm/avm_codec.h).
OBU_SEQUENCE_HEADER = 1
OBU_TEMPORAL_DELIMITER = 2
OBU_MULTI_FRAME_HEADER = 3
OBU_CLOSED_LOOP_KEY = 4
OBU_OPEN_LOOP_KEY = 5
OBU_LEADING_TILE_GROUP = 6
OBU_REGULAR_TILE_GROUP = 7
OBU_METADATA_SHORT = 8
OBU_METADATA_GROUP = 9
OBU_SWITCH = 10
OBU_LEADING_SEF = 11
OBU_REGULAR_SEF = 12
OBU_LEADING_TIP = 13
OBU_REGULAR_TIP = 14
OBU_BUFFER_REMOVAL_TIMING = 15
OBU_LAYER_CONFIGURATION_RECORD = 16
OBU_ATLAS_SEGMENT = 17
OBU_OPERATING_POINT_SET = 18
OBU_BRIDGE_FRAME = 19
OBU_MULTI_STREAM_DECODER_OPERATION = 20
OBU_RAS_FRAME = 21
OBU_QUANTIZATION_MATRIX = 22
OBU_FILM_GRAIN_MODEL = 23
OBU_CONTENT_INTERPRETATION = 24
OBU_PADDING = 25

# Metadata types (avm/avm_codec.h).
META_HDR_CLL = 1
META_ITUT_T35 = 3
META_TIMECODE = 4


def uleb(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def obu(obu_type, payload=b"", tlayer=0):
    """One AV2 OBU: uleb size (includes header) + header byte + payload."""
    header = bytes([(0 << 7) | ((obu_type & 0x1F) << 2) | (tlayer & 0x03)])
    return uleb(len(header) + len(payload)) + header + payload


def ivf_header(knobs):
    assert len(knobs) == 4
    return (b"DKIF" + struct.pack("<HH", 0, 32) + b"AV02" +
            struct.pack("<HH", 64, 64) + struct.pack("<I", knobs[0]) +
            struct.pack("<I", knobs[1]) + struct.pack("<I", knobs[2]) +
            struct.pack("<I", knobs[3]))


def frame(payload, ts_bits):
    """IVF frame: 4-byte size + 8-byte timestamp (knob bytes) + payload."""
    return struct.pack("<I", len(payload)) + struct.pack("<Q", ts_bits) + payload


def metadata_short(meta_type, cancel, suffix=0):
    """OBU_METADATA_SHORT payload (av2/decoder/obu.c read_metadata_short):
    suffix bit, layer_idc(3), cancel bit, persistence(3), uleb type."""
    b0 = ((suffix & 1) << 7) | ((1 & 0x07) << 4) | ((cancel & 1) << 3) | 1
    return obu(OBU_METADATA_SHORT, bytes([b0]) + uleb(meta_type))


def make_seeds():
    td = obu(OBU_TEMPORAL_DELIMITER)
    td_all = obu(OBU_TEMPORAL_DELIMITER, b"", tlayer=3)
    pad = obu(OBU_PADDING, bytes(range(8)))
    pad_long = obu(OBU_PADDING, bytes((i * 7) & 0xFF for i in range(64)))
    seq_garbage = obu(OBU_SEQUENCE_HEADER, bytes([0x40, 0x0A, 0x2B, 0x05, 0xFF]))
    mfh = obu(OBU_MULTI_FRAME_HEADER, b"\x00")  # uvlc ids 0, size-present 0
    mfh2 = obu(OBU_MULTI_FRAME_HEADER, b"\x08\x14", tlayer=1)
    tileg = obu(OBU_REGULAR_TILE_GROUP, bytes([0x55] * 12))
    tileg_lead = obu(OBU_LEADING_TILE_GROUP, bytes([0xAA] * 6))
    key4 = obu(OBU_CLOSED_LOOP_KEY, bytes([0x11, 0x22, 0x33]))
    key5 = obu(OBU_OPEN_LOOP_KEY, bytes([0x44, 0x55]))
    switch = obu(OBU_SWITCH, bytes([0x0F, 0xF0]))
    sef = obu(OBU_LEADING_SEF, bytes([0x5A] * 5))
    sef2 = obu(OBU_REGULAR_SEF, bytes([0xA5] * 5))
    tip = obu(OBU_LEADING_TIP, bytes([0x3C] * 4))
    tip2 = obu(OBU_REGULAR_TIP, bytes([0xC3] * 4))
    brt = obu(OBU_BUFFER_REMOVAL_TIMING, bytes([0x18, 0x81]))
    lcr = obu(OBU_LAYER_CONFIGURATION_RECORD, bytes([0x66] * 6))
    atlas = obu(OBU_ATLAS_SEGMENT, bytes([0x77] * 7))
    ops = obu(OBU_OPERATING_POINT_SET, bytes([0x01, 0x02, 0x03, 0x04]))
    bridge = obu(OBU_BRIDGE_FRAME, bytes([0x88] * 8))
    msdo = obu(OBU_MULTI_STREAM_DECODER_OPERATION, bytes([0x99] * 4))
    ras = obu(OBU_RAS_FRAME, bytes([0xAB] * 6))
    qm = obu(OBU_QUANTIZATION_MATRIX, bytes([0xCD] * 16))
    fgm = obu(OBU_FILM_GRAIN_MODEL, bytes([0xEF] * 24))
    ci = obu(OBU_CONTENT_INTERPRETATION, bytes([0x01, 0xFE]))
    reserved = bytes([(0 << 7) | ((26 & 0x1F) << 2)])
    reserved_obu = uleb(1 + 3) + reserved + bytes([0x12, 0x34, 0x56])

    return [
        ("td_only", [td], 0x12345678, (0x5A, 0x5A, 0x15, 0x5A)),
        ("td_pad", [td, pad, pad_long], 0x2AAAAAAAAAAAAA, (0x5A, 0x00, 0x00, 0xA5)),
        ("meta_t35_cancel", [td, metadata_short(META_ITUT_T35, 1)],
         0x1555555555555555, (0xA5, 0x00, 0x00, 0x00)),
        ("meta_hdrcll_cancel", [metadata_short(META_HDR_CLL, 1)],
         0x0555555555555555, (0x00, 0x5A, 0x00, 0x00)),
        ("meta_timecode", [td, metadata_short(META_TIMECODE, 0)],
         0x2AAAAAAAAA, (0x15, 0x00, 0x00, 0xA5)),
        ("meta_group", [obu(OBU_METADATA_GROUP, bytes([0x01, 0x00, 0x80]))],
         0x4000000000000000, (0x00, 0x00, 0x2A, 0x00)),
        ("seq_garbage", [td, seq_garbage], 0x133333333, (0x5A, 0x15, 0x00, 0x5A)),
        ("mfh", [td, mfh, mfh2], 0x44444444, (0x00, 0x5A, 0x00, 0x00)),
        ("tile_groups", [td, tileg, tileg_lead], 0xC000000, (0x5A, 0x00, 0x2A, 0xA5)),
        ("keys_switch", [key4, key5, switch], 0xC0, (0xA5, 0x2A, 0x00, 0x00)),
        ("sef_tip", [sef, sef2, tip, tip2], 0x280, (0x5A, 0x5A, 0x5A, 0x5A)),
        ("timing_lcr", [brt, lcr], 0x8000, (0x00, 0xA5, 0x00, 0xA5)),
        ("atlas_ops", [atlas, ops], 0x200000, (0xA5, 0x00, 0x5A, 0x00)),
        ("bridge_msdo", [bridge, msdo], 0x10000, (0x00, 0x00, 0xA5, 0x5A)),
        ("ras_qm", [ras, qm], 0x4000, (0x5A, 0x2A, 0x00, 0x00)),
        ("filmgrain_ci", [fgm, ci], 0x2000, (0x2A, 0xA5, 0x15, 0x00)),
        ("reserved", [reserved_obu], 0x1000, (0xA5, 0x5A, 0xA5, 0x00)),
        ("all_obus", [td_all, pad, metadata_short(META_ITUT_T35, 1), mfh,
                      tileg, switch, tip, brt, ops, fgm, pad],
         0xFFFFFFFF, (0xFF, 0x5A, 0x2A, 0xA5)),
    ]


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_av2_dec_fuzzer_seeds.py <output-directory>")
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    seeds = make_seeds()
    for name, obus, ts, knobs in seeds:
        data = ivf_header(knobs) + frame(b"".join(obus), ts)
        with open(os.path.join(out_dir, "avm_%s.ivf" % name), "wb") as f:
            f.write(data)
    print("wrote %d seeds to %s" % (len(seeds), out_dir))


if __name__ == "__main__":
    main()