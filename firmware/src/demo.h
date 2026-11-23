#pragma once
// Demo traffic for the workshop sniffer: a synthetic 16-panel swarm, so the
// display and the laptop tools can be developed and shown with no wall in
// radio range. Nothing is transmitted. Each frame is built as the 128-byte
// buffer the ESP8266 promiscuous callback delivers (see sniff_parse.h) and is
// handed to the normal decoder, so the demo exercises the real parsing path.
// No Arduino dependencies; tests/parse_test.cpp checks every frame it makes.
//
// workshop-transmitter sends the same frames on air from a second module.
//
// The demo swarm lives on one channel (CHANNEL) so SCAN has to find it. Its
// MAC addresses are locally administered (02:F1:0C:...) and match no device.
#include <cstdint>
#include <cstring>

namespace demo {

constexpr uint8_t CHANNEL = 13;
constexpr int PANELS = 16, CONTROLLER = 16;
constexpr uint32_t FRAME_MS = 20;       // gap between demo frames
constexpr uint32_t DROP_PERIOD_S = 120; // D4 is silent for the last 50 s of each period
constexpr uint32_t DROP_FROM_S = 70;

inline void mac(uint8_t out[6], int who) {
  static const uint8_t base[5] = {0x02, 0xF1, 0x0C, 0x00, 0x00};
  memcpy(out, base, 5);
  out[5] = who == CONTROLLER ? 0xFF : uint8_t(0x10 + who);
}

struct State {
  uint32_t next_ms = 0;
  uint32_t seq = 1000;     // fleet heartbeat sequence
  uint32_t rnd = 0x2545F491;
  uint8_t requester = 0;   // panel whose turn it is
  uint8_t step = 0;        // 0 request, 1..15 replies, 16 poll, 17 health
  uint16_t frame_seq = 0;  // 802.11 sequence number
};

inline uint32_t rand32(State& s) {
  s.rnd = s.rnd * 1664525u + 1013904223u;
  return s.rnd >> 8;
}

// Signal strength of a panel: strongest at A1 and weaker towards D4, with a
// slow swing of a few dB and some jitter, so the signal map moves.
inline int8_t rssi(State& s, int panel, uint32_t now_ms) {
  int base = -46 - 3 * (panel % 4) - 5 * (panel / 4);
  int t = int((now_ms / 500 + uint32_t(panel) * 7) % 16);
  int swing = (t < 8 ? t : 16 - t) - 4;
  return int8_t(base + swing + int(rand32(s) % 5) - 2);
}

inline bool silent(int panel, uint32_t now_ms) {
  return panel == 15 && (now_ms / 1000) % DROP_PERIOD_S >= DROP_FROM_S;
}

// Largest frame the generator makes: header and vendor element (39 bytes)
// plus a full FLK2 frame (40 + 160 + 32).
constexpr uint16_t AIR_MAX = 39 + 232;

// 802.11 action header and ESP-NOW vendor element, written at `f` as the
// frame goes on air (no capture prefix, no FCS). Returns a pointer to where
// the ESP-NOW payload goes; the frame is 39 + body bytes long.
inline uint8_t* open_frame(State& s, uint8_t* f, int from, int to, uint16_t body) {
  memset(f, 0, 39);
  f[0] = 0xD0; f[2] = 0x3A; f[3] = 0x01;
  if (to < 0) memset(f + 4, 0xFF, 6); else mac(f + 4, to);
  mac(f + 10, from);
  memset(f + 16, 0xFF, 6);
  uint16_t sc = uint16_t(s.frame_seq++ << 4);
  f[22] = uint8_t(sc); f[23] = uint8_t(sc >> 8);
  f[24] = 0x7F; f[25] = 0x18; f[26] = 0xFE; f[27] = 0x34;
  for (int i = 28; i < 32; i++) f[i] = uint8_t(rand32(s));
  f[32] = 0xDD; f[33] = uint8_t(body + 5 > 255 ? 255 : body + 5);
  f[34] = 0x18; f[35] = 0xFE; f[36] = 0x34; f[37] = 0x04; f[38] = 0x02;
  return f + 39;
}

inline void put32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
}

// FLK1 heartbeat: kind 1 is a broadcast request, kind 2 a unicast reply.
inline uint16_t flk1(State& s, uint8_t* f, int from, int to, uint8_t kind, uint32_t seq) {
  uint8_t* p = open_frame(s, f, from, to, 20);
  p[0] = 0x31; p[1] = 0x4B; p[2] = 0x4C; p[3] = 0x46;
  p[4] = 1; p[5] = kind;
  p[6] = uint8_t('A' + from / 4); p[7] = uint8_t('1' + from % 4);
  put32(p + 8, seq);
  put32(p + 12, seq * 2654435761u); put32(p + 16, ~seq);
  return 39 + 20;
}

// FLK2 management frame with a random nonce and a random (unverifiable) tag.
inline uint16_t flk2(State& s, uint8_t* f, int from, int to, uint8_t kind, uint16_t plen,
                     const uint8_t* payload) {
  uint16_t body = uint16_t(40 + plen + 32);
  uint8_t* p = open_frame(s, f, from, to, body);
  memcpy(p, "FLK2", 4);
  p[4] = 1; p[5] = kind;
  p[6] = uint8_t(plen); p[7] = uint8_t(plen >> 8);
  mac(p + 8, from); mac(p + 14, to);
  for (int i = 20; i < 36; i++) p[i] = uint8_t(rand32(s));
  put32(p + 36, 1);
  if (plen) memcpy(p + 40, payload, plen);
  for (int i = 0; i < 32; i++) p[40 + plen + i] = uint8_t(rand32(s));
  return uint16_t(39 + body);
}

// Produce the next demo frame, as sent on air, if one is due. `frame` must
// hold AIR_MAX bytes. `level` is the signal strength the frame should appear
// to have. Returns false when nothing is due, or when the panel whose turn it
// is has gone silent.
inline bool next_air(State& s, uint32_t now_ms, uint8_t* frame, uint16_t& len, int8_t& level) {
  if (int32_t(now_ms - s.next_ms) < 0) return false;
  s.next_ms = now_ms + FRAME_MS;
  int req = s.requester;
  uint8_t step = s.step;
  if (++s.step == 18) { s.step = 0; s.requester = uint8_t((req + 1) % PANELS); s.seq++; }
  if (step == 0) {
    if (silent(req, now_ms)) return false;
    level = rssi(s, req, now_ms);
    len = flk1(s, frame, req, -1, 1, s.seq);
    return true;
  }
  if (step <= 15) {
    int from = (req + step) % PANELS;
    if (silent(from, now_ms) || silent(req, now_ms)) return false;
    level = rssi(s, from, now_ms);
    len = flk1(s, frame, from, req, 2, s.seq);
    return true;
  }
  if (step == 16) {
    level = -40;
    len = flk2(s, frame, CONTROLLER, req, 1, 0, nullptr);
    return true;
  }
  if (silent(req, now_ms)) return false;
  uint8_t health[128];
  memset(health, 0, sizeof(health));
  health[0] = uint8_t('A' + req / 4); health[1] = uint8_t('1' + req % 4);
  health[2] = 1; health[3] = 1;
  memcpy(health + 4, "0.10.4-demo", 11);
  level = rssi(s, req, now_ms);
  len = flk2(s, frame, req, CONTROLLER, 2, 128, health);
  return true;
}

// The same frame as the ESP8266 promiscuous callback would deliver it: a
// 12-byte prefix carrying the signal strength, the first 112 bytes of the
// frame, and a trailer with the on-air length including the 4-byte FCS. A
// HEALTH reply is therefore cut short exactly as a real one is.
inline bool next(State& s, uint32_t now_ms, uint8_t buf[128]) {
  uint8_t frame[AIR_MAX];
  uint16_t len = 0;
  int8_t level = 0;
  if (!next_air(s, now_ms, frame, len, level)) return false;
  memset(buf, 0, 128);
  buf[0] = uint8_t(level);
  memcpy(buf + 12, frame, len < 112 ? len : 112);
  uint16_t air = uint16_t(len + 4);
  buf[124] = 1;
  buf[126] = uint8_t(air); buf[127] = uint8_t(air >> 8);
  return true;
}

}  // namespace demo
