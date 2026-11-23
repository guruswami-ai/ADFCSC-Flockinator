#pragma once
// Pure frame parsing for the workshop sniffer — no Arduino dependencies, so
// the same code is unit-tested natively against the swarm's wire.h encoder
// (tests/parse_test.cpp). Layouts: the swarm management protocol and
// the FLK1 Probe in the node firmware.
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace sniff {

constexpr uint16_t FLK1_SIZE = 20;
constexpr uint16_t FLK2_HEADER = 40, FLK2_TAG = 32, FLK2_MAX_PAYLOAD = 160;

// ESP8266 Arduino core 3.x (NONOS SDK 3.0) promiscuous callbacks prepend a
// 12-byte RX-info block before the 802.11 header; byte 0 is the signed RSSI.
// Verified on hardware 2026-11-20 against node FLK1 replies and a probe
// request (tests/parse_test.cpp covers the view math).
constexpr uint16_t RX_PREFIX = 12;

inline uint16_t get16(const uint8_t* p) { return uint16_t(p[0]) | uint16_t(p[1]) << 8; }
inline int16_t geti16(const uint8_t* p) { return int16_t(get16(p)); }
inline uint32_t get32(const uint8_t* p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint64_t get64(const uint8_t* p) { return uint64_t(get32(p)) | uint64_t(get32(p + 4)) << 32; }

// Management frames always arrive as a fixed 128-byte buffer: the 12-byte
// RX-info block, the first 112 bytes of the frame, a u16 count and a u16
// on-air length that includes the 4-byte FCS. Verified on hardware
// 2026-11-20: a 59-byte FLK1 action frame reports len 128 and air length 63.
// Anything past frame byte 112 never reaches the callback, so a longer frame
// is truncated; `air_len` says how long it really was.
constexpr uint16_t MGMT_CAPTURE = 128, MGMT_FRAME_MAX = 112, FCS_LEN = 4;

struct RxView { const uint8_t* frame; uint16_t len; int8_t rssi; uint16_t air_len; };
inline RxView rx_view(const uint8_t* buf, uint16_t n) {
  if (n <= RX_PREFIX) return {nullptr, 0, 0, 0};
  uint16_t len = uint16_t(n - RX_PREFIX), air = 0;
  if (n == MGMT_CAPTURE) {
    air = get16(buf + MGMT_CAPTURE - 2);
    len = MGMT_FRAME_MAX;
    if (air >= FCS_LEN && air - FCS_LEN < len) len = uint16_t(air - FCS_LEN);
  }
  return {buf + RX_PREFIX, len, int8_t(buf[0]), air};
}

// True for 802.11 management frames (frame-control type bits 00). The type
// bits are in the first header byte, after the RX-info prefix. Byte 0 of the
// capture buffer is RSSI and must not be used for this test.
inline bool is_management(const uint8_t* buf, uint16_t n) {
  return n > RX_PREFIX && (buf[RX_PREFIX] & 0x0C) == 0x00;
}

struct Flk1 {
  uint8_t kind;        // 1 = broadcast request, 2 = unicast reply
  char label[2];       // A1..D4, not NUL-terminated
  uint32_t seq;
  uint64_t nonce;
};

struct Flk2 {
  uint8_t kind;        // 1..14
  uint16_t plen;
  const uint8_t* sender;   // MAC[6]
  const uint8_t* target;   // MAC[6]
  const uint8_t* nonce;    // [16]
  uint32_t seq;
  const uint8_t* payload;  // payload_avail bytes are readable (plen if complete)
  const uint8_t* tag;      // 32-byte HMAC (presence only); null when truncated
  uint16_t payload_avail;  // payload bytes actually captured
  bool truncated;          // capture ended before the end of the tag
};

// Locate the ESP-NOW payload inside a captured 802.11 management action
// frame: category 0x7F + Espressif OUI 18:FE:34, then a vendor-specific
// prefix of varying length (ESP32 and ESP8266 differ). Returns the offset of
// the FLK1/FLK2 magic, or -1. `n` is the full captured frame length.
inline int payload_offset(const uint8_t* b, uint16_t n) {
  if (n < 28 || (b[0] & 0xF0) != 0xD0) return -1;   // management action only
  if (b[24] != 0x7F || b[25] != 0x18 || b[26] != 0xFE || b[27] != 0x34) return -1;
  uint16_t limit = n > 60 ? 60 : n;
  for (uint16_t p = 28; p + 4 <= limit; p++) {
    if (!memcmp(b + p, "FLK2", 4)) return p;
    if (b[p] == 0x31 && b[p + 1] == 0x4B && b[p + 2] == 0x4C && b[p + 3] == 0x46) return p;
  }
  return -1;
}

inline bool parse_flk1(const uint8_t* p, size_t avail, Flk1& out) {
  if (avail < FLK1_SIZE || p[4] != 1 || (p[5] != 1 && p[5] != 2)) return false;
  out.kind = p[5];
  out.label[0] = char(p[6]); out.label[1] = char(p[7]);
  out.seq = get32(p + 8);
  out.nonce = get64(p + 12);
  return true;
}

// --- FLK1 presentation frames (Phase 2 swarm telemetry) ---------------------
// Three UNAUTHENTICATED frames the panels broadcast so the swarm can share a
// picture and react to reported contacts. They carry the same "1KLF" magic as
// the heartbeat but distinct kind bytes and distinct lengths, so each is
// recognised by its exact size. Layouts: the node firmware
// (Telem/Contact), the node firmware (Claim/roles).
// These are the frames students decode and forge in the workshop.
constexpr uint16_t FLK3_SIZE = 22, FLK4_SIZE = 18, FLK5_SIZE = 16;

// kind=3: a node's self-report of where it is and what it is doing.
struct Flk3 {
  char label[2];       // A1..D4
  int16_t x, y, z;     // world position
  uint16_t heading;    // 0..359, clockwise
  uint8_t state;       // recon state enum
  uint8_t flags;       // bit0 rogue, bit1 active (airborne), bit2 friendly/BLU
  uint32_t seq;
};
// kind=4 (version 2): a contact report — the swarm's belief about a virtual
// target. The primary forgery surface: any class/confidence can be asserted.
struct Flk4 {
  uint8_t id;          // contact slot 0..7
  int16_t x, y;        // world position
  uint8_t cls;         // 0 UNKNOWN, 1 BLU, 2 RED, 3 CIV
  uint8_t conf;        // 0..255 belief strength
  uint8_t flags;       // bit0 active, bit1 high-value, bit2 support-called, bit3 committed (BGO)
  uint32_t seq;
};
// kind=5: a node's claim — its bid (range) and role on one contact, so the
// swarm splits attacker / observer / yield with no central brain.
struct Flk5 {
  char label[2];       // A1..D4
  uint8_t contact;     // contact slot this claim is about
  uint8_t role;        // 1 LEAD, 2 SUPPORT, 3 YIELD
  uint16_t dist;       // range to the contact
  uint32_t seq;
};

inline bool is_flk1_magic(const uint8_t* p) {
  return p[0] == 0x31 && p[1] == 0x4B && p[2] == 0x4C && p[3] == 0x46;  // "1KLF"
}
inline bool parse_flk3(const uint8_t* p, size_t avail, Flk3& out) {
  if (avail < FLK3_SIZE || !is_flk1_magic(p) || p[4] != 1 || p[5] != 3) return false;
  out.label[0] = char(p[6]); out.label[1] = char(p[7]);
  out.x = geti16(p + 8); out.y = geti16(p + 10); out.z = geti16(p + 12);
  out.heading = get16(p + 14); out.state = p[16]; out.flags = p[17];
  out.seq = get32(p + 18);
  return true;
}
inline bool parse_flk4(const uint8_t* p, size_t avail, Flk4& out) {
  if (avail < FLK4_SIZE || !is_flk1_magic(p) || p[4] != 2 || p[5] != 4) return false;
  out.id = p[6];
  out.x = geti16(p + 7); out.y = geti16(p + 9);
  out.cls = p[11]; out.conf = p[12]; out.flags = p[13];
  out.seq = get32(p + 14);
  return true;
}
inline bool parse_flk5(const uint8_t* p, size_t avail, Flk5& out) {
  if (avail < FLK5_SIZE || !is_flk1_magic(p) || p[4] != 1 || p[5] != 5) return false;
  out.label[0] = char(p[6]); out.label[1] = char(p[7]);
  out.contact = p[8]; out.role = p[9];
  out.dist = get16(p + 10); out.seq = get32(p + 12);
  return true;
}

// Header-first parse: succeeds whenever the 40-byte header was captured, and
// reports how much of the payload is readable. The ESP8266 shows at most 73
// ESP-NOW payload bytes of a frame, so every FLK2 reply longer than a POLL
// arrives truncated.
inline bool parse_flk2_partial(const uint8_t* p, size_t avail, Flk2& out) {
  if (avail < FLK2_HEADER) return false;
  if (memcmp(p, "FLK2", 4) || p[4] != 1 || p[5] < 1 || p[5] > 14) return false;
  uint16_t plen = get16(p + 6);
  if (plen > FLK2_MAX_PAYLOAD) return false;
  size_t body = avail - FLK2_HEADER;
  out.kind = p[5];
  out.plen = plen;
  out.sender = p + 8;
  out.target = p + 14;
  out.nonce = p + 20;
  out.seq = get32(p + 36);
  out.payload = p + FLK2_HEADER;
  out.payload_avail = uint16_t(body < plen ? body : plen);
  out.truncated = avail < size_t(FLK2_HEADER + plen + FLK2_TAG);
  out.tag = out.truncated ? nullptr : p + FLK2_HEADER + plen;
  return true;
}

// Complete frames only (header, whole payload, whole tag).
inline bool parse_flk2(const uint8_t* p, size_t avail, Flk2& out) {
  Flk2 f{};
  if (!parse_flk2_partial(p, avail, f) || f.truncated) return false;
  out = f;
  return true;
}

}  // namespace sniff