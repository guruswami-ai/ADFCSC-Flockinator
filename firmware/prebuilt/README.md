# Prebuilt firmware

`flockinator-sniffer-esp8266.bin` — the combined sniffer + injector, ready to
flash to an ESP8266 (ESP-12E / NodeMCU-style board) at offset `0x0`.

No toolchain? Flash it directly — see [`../../docs/flashing.md`](../../docs/flashing.md).
Prefer to build from source? `cd ..` then `pio run -t upload`.
