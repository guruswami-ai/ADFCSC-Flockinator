# Flockinator — ESP-NOW Swarm Attack Workshop

A hands-on lab in attacking an **unauthenticated wireless swarm**. A wall of 16
LED panels runs a simulated drone swarm that coordinates over **ESP-NOW** (the
2.4 GHz peer-to-peer protocol built into ESP32/ESP8266). The swarm's chatter —
telemetry, target contacts, and role claims — is broadcast **in the clear and
unauthenticated**. Your job: capture it, understand it, and forge it to
**degrade the swarm's missions** — ideally without the commander noticing.

This repo is everything you need to join in from a laptop and an ESP8266.

## The lesson in one sentence

The same radio chatter that lets a swarm coordinate is exactly what lets an
attacker break it — authentication is the difference between a swarm you can
only *watch* and one you can *command*.

## Your kit

- An **ESP8266** board (ESP-12E / NodeMCU style) with a small OLED — flashed
  with the combined **sniffer + injector** tool in this repo.
- A **Kali Linux** laptop.
- A **USB-C cable into a USB-A port** on the laptop (the board is powered from
  the 5 V a USB-A port supplies — see [`docs/flashing.md`](docs/flashing.md)).

## Quickstart (≈60 seconds)

1. Flash the board — [`docs/flashing.md`](docs/flashing.md). No toolchain? Use
   the prebuilt binary in [`firmware/prebuilt/`](firmware/prebuilt/).
2. Open the serial monitor at **115200 baud**. The tool boots in **SNIFF** mode.
3. Type `FIND` — it scans the band and locks onto the swarm's channel.
4. Watch the swarm's traffic stream past as JSON. You're now inside the net.

Then work through [`docs/exercises.md`](docs/exercises.md): capture → decode →
extract → inject → degrade the missions.

## What's here

| Path | What |
|---|---|
| [`firmware/`](firmware/) | The combined sniffer+injector (PlatformIO source + prebuilt `.bin`) |
| [`docs/flashing.md`](docs/flashing.md) | Install the tools on Kali, wire up the board, flash it |
| [`docs/protocol.md`](docs/protocol.md) | The swarm's wire frames — the forgeable surface |
| [`docs/exercises.md`](docs/exercises.md) | The attacks: replay, spoof, flood, manipulate |
| [`docs/instructor.md`](docs/instructor.md) | Session outline for facilitators |

## Rules of engagement

This is a **sanctioned exercise against a simulated swarm on an isolated lab
network**. Everything here is for learning to *defend* unauthenticated IoT and
mesh protocols. Don't point these techniques at radios, networks, or devices
you don't own or aren't authorised to test.

See [`LICENSE`](LICENSE).
