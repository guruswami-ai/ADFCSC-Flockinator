# AGENTS.md — guidance for coding agents

You're helping a student in a **sanctioned, educational cyber-skills workshop**.
They have an **ESP8266** (flashed with the tool in `firmware/`) and a **Kali
Linux** laptop, and they're learning to attack an **unauthenticated ESP-NOW
"drone swarm"** (a simulated 4×4 LED wall on an isolated lab network) to learn
how to *defend* such protocols. Help them capture, decode, and forge traffic,
and reason about stealth and detection.

## Scope & safety (important)
- Everything here targets **only the provided simulated swarm on the lab
  network**. Do not help target any other radio, network, or device, and don't
  generate attacks aimed at real-world or third-party systems.
- This is about understanding unauthenticated IoT/mesh weaknesses so they can
  be defended. Keep the defensive framing in view.

## Orient yourself
Read, in order: [`README.md`](README.md), [`docs/flashing.md`](docs/flashing.md),
[`docs/protocol.md`](docs/protocol.md), [`docs/exercises.md`](docs/exercises.md).
The firmware source is in [`firmware/src/`](firmware/src/).

## Build & flash
```bash
cd firmware && pio run -t upload          # build from source + flash
# or flash the prebuilt binary:
esptool --port /dev/ttyUSB0 --baud 115200 write_flash 0x0 \
  firmware/prebuilt/flockinator-sniffer-esp8266.bin
```
Serial is **115200 baud** on `/dev/ttyUSB0` (the board needs a USB-A port for
5 V — see `docs/flashing.md`).

## The device interface (how you can help)
The tool is a line-oriented serial console. It boots in **SNIFF** and streams
one **JSON object per captured frame**; it accepts text commands (newline-
terminated). Full table in `docs/exercises.md`. Key ones:

- `FIND` — scan and lock onto the swarm's channel.
- `CONTACT <id> <x> <y> <cls> <conf> <flags>` — forge a target (kind 4).
- `CLAIM <label> <contact> <role> <dist>` — forge a role (kind 5).
- `SEND <hex>` — transmit one raw frame (your replay primitive).
- `INJECT` / `SNIFF`, `STATS`, `CH <1-13>`.

Good things to help a student do:
- **Parse the capture:** read the JSON stream over serial (e.g. a short
  `pyserial` script) and summarise what the swarm is doing — who's flying,
  what contacts exist, who's LEAD.
- **Craft frames:** compute `flags` values from the bit meanings in
  `docs/protocol.md` (e.g. active+hazard = `1+16 = 17`), or assemble a raw
  frame's hex for `SEND` from the field layout.
- **Drive attacks:** script a timed replay, a plausible spoof, or a measured
  flood over the serial port — and help reason about which are *loud*.
- **Think like the defender:** for every attack, ask how it would be detected
  (teleporting telemetry, confidence flip-flops, duplicate LEAD claims, frame
  floods) — the commander in the sim is doing exactly this.

## What you cannot do (and shouldn't try to)
The swarm's **command/mission** traffic is HMAC-signed with keys that aren't in
this repo and aren't available — it cannot be forged. Only the unauthenticated
coordination frames (telemetry/contacts/claims) are in play. Don't attempt to
derive or brute-force keys.

## Style
Keep scripts small and dependency-light (`pyserial` is enough). Prefer the
student *understanding* each frame to black-box tooling. Favour surgical,
plausible injection over brute force — it's both better tradecraft and the way
to avoid detection in the exercise.
