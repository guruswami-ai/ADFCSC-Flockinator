#pragma once
// Minimal SSD1306 128x64 I2C driver for the workshop sniffer. No external
// libraries: renders the swarm's own 3x5 font (firmware/shared/recon/font.h)
// at 2x scale so the OLED matches the panel vocabulary. Pin pairs are probed
// at boot because the donated ESP8266 OLED boards vary in wiring.
#include <Arduino.h>
#include <Wire.h>
#include <cstring>
#include "recon_font.h"

namespace oled {

// Many of these 0.96" modules are two-colour: the top 16 pixel rows are
// yellow and the lower 48 are blue, with a thin dark gap between. That is a
// fixed property of the glass, not something the driver controls. The layout
// therefore puts one header row in the top band and four body rows below it,
// so no line of text straddles the colour boundary. It reads the same on a
// single-colour module.
constexpr int WIDTH = 128, HEIGHT = 64, ROWS = 5, COLS = 18;
constexpr int HEADER_H = 16, BODY_PITCH = 12;
inline int row_top(int r) { return r == 0 ? 0 : HEADER_H + (r - 1) * BODY_PITCH; }
inline int row_height(int r) { return r == 0 ? HEADER_H : BODY_PITCH; }
inline uint8_t addr = 0;
inline int pin_sda = -1, pin_scl = -1;
inline uint8_t fb[WIDTH * HEIGHT / 8];
inline char shadow[ROWS][COLS + 1];
inline bool present = false;

inline bool probe(uint8_t a) {
  Wire.beginTransmission(a);
  return Wire.endTransmission() == 0;
}

inline void cmd(uint8_t c) {
  Wire.beginTransmission(addr);
  Wire.write(0x00);
  Wire.write(c);
  Wire.endTransmission();
}

inline void init() {
  cmd(0xAE);              // display off
  cmd(0xD5); cmd(0x80);   // clock divide
  cmd(0xA8); cmd(0x3F);   // multiplex 64
  cmd(0xD3); cmd(0x00);   // display offset
  cmd(0x40);              // start line 0
  cmd(0x8D); cmd(0x14);   // charge pump on
  cmd(0x20); cmd(0x00);   // horizontal addressing
  cmd(0xA1);              // segment remap
  cmd(0xC8);              // COM scan decrement
  cmd(0xDA); cmd(0x12);   // COM pins for 128x64
  cmd(0x81); cmd(0xCF);   // contrast
  cmd(0xD9); cmd(0xF1);   // precharge
  cmd(0xDB); cmd(0x40);   // VCOMH deselect
  cmd(0xA4);              // resume from RAM
  cmd(0xA6);              // normal (not inverted)
  cmd(0xAF);              // display on
  memset(fb, 0, sizeof(fb));
  memset(shadow, 0, sizeof(shadow));
}

inline bool detect() {
  static const int pairs[][2] = {
      {4, 5}, {5, 4}, {14, 12}, {12, 14}, {0, 2},
      {2, 0}, {13, 12}, {12, 13}, {9, 10}, {10, 9}};
  for (const auto& p : pairs) {
    Wire.begin(p[0], p[1]);
    Wire.setClock(400000);
    for (uint8_t a : {0x3C, 0x3D}) {
      if (probe(a)) {
        addr = a; pin_sda = p[0]; pin_scl = p[1];
        init(); present = true;
        return true;
      }
    }
  }
  present = false;
  return false;
}

inline bool force_pins(int sda, int scl) {
  Wire.begin(sda, scl);
  Wire.setClock(400000);
  for (uint8_t a : {0x3C, 0x3D}) {
    if (probe(a)) {
      addr = a; pin_sda = sda; pin_scl = scl;
      init(); present = true;
      return true;
    }
  }
  return false;
}

inline void pixel(int x, int y, bool on) {
  if (x < 0 || x >= WIDTH || y < 0 || y >= HEIGHT) return;
  uint8_t mask = 1 << (y % 8);
  if (on) fb[x + (y / 8) * WIDTH] |= mask;
  else fb[x + (y / 8) * WIDTH] &= ~mask;
}

// 3x5 glyph at 2x scale (6x10 pixels), 7px advance: 18 columns x 5 rows.
inline void text(int x, int y, const char* s) {
  for (; *s; s++, x += 7) {
    unsigned b = recon::glyph(*s);
    for (int yy = 0; yy < 5; yy++)
      for (int xx = 0; xx < 3; xx++)
        if (b & (1u << (14 - yy * 3 - xx)))
          for (int dy = 0; dy < 2; dy++)
            for (int dx = 0; dx < 2; dx++)
              pixel(x + xx * 2 + dx, y + yy * 2 + dy, true);
  }
}

inline void row(int r, const char* s) {
  if (r < 0 || r >= ROWS) return;
  char line[COLS + 1];
  snprintf(line, sizeof(line), "%-18s", s);
  line[COLS] = 0;
  strncpy(shadow[r], line, COLS + 1);
  for (int x = 0; x < WIDTH; x++)
    for (int y = row_top(r); y < row_top(r) + row_height(r); y++) pixel(x, y, false);
  text(0, row_top(r) + (row_height(r) - 10) / 2, line);
}

// The same glyphs at 1x scale (3x5 pixels), 4px advance, for chart labels.
inline void text_small(int x, int y, const char* s, bool on = true) {
  for (; *s; s++, x += 4) {
    unsigned b = recon::glyph(*s);
    for (int yy = 0; yy < 5; yy++)
      for (int xx = 0; xx < 3; xx++)
        if (b & (1u << (14 - yy * 3 - xx))) pixel(x + xx, y + yy, on);
  }
}

inline void fill_rect(int x, int y, int w, int h, bool on) {
  for (int xx = x; xx < x + w; xx++)
    for (int yy = y; yy < y + h; yy++) pixel(xx, yy, on);
}

// Set the text that DUMP reports for a row without drawing it, for pages
// that draw graphics in the body.
inline void note(int r, const char* s) {
  if (r < 0 || r >= ROWS) return;
  snprintf(shadow[r], COLS + 1, "%-18.18s", s);
}

inline void flush() {
  if (!present) return;
  cmd(0x21); cmd(0); cmd(WIDTH - 1);   // column window
  cmd(0x22); cmd(0); cmd(7);           // page window
  for (int chunk = 0; chunk < 16; chunk++) {
    Wire.beginTransmission(addr);
    Wire.write(0x40);
    Wire.write(fb + chunk * 64, 64);
    Wire.endTransmission();
  }
}

}  // namespace oled