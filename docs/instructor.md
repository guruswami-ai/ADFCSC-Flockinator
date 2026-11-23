# Facilitator outline

**Format:** two 3-hour sessions (0900–1200 and 1300–1600), up to 25 students
each. Each student has an ESP8266 kit and a Kali laptop; a shared 4×4 LED wall
runs the live swarm on an isolated lab network.

With ~25 radios injecting at once the air gets noisy — that's intentional, and
part of the realism. Encourage students to be surgical rather than loud.

## Part 1 — Swarms & why communication is the weakness (≈50 min)

- What a swarm is; swarm intelligence and **emergent** behaviour from simple
  local rules (flocking, stigmergy, decentralised task allocation).
- How the panels' swarm coordinates with **no central brain**: shared
  telemetry, target contacts, and role claims, each node deciding locally.
- The core idea: **communication is both the enabler and the attack surface.**
  Unauthenticated coordination means anyone on the channel is a voting member.
- Short demo: run a clean mission on the wall; name the behaviours out loud
  (search, detect, converge, assign roles, engage, return).

## Part 2 — ESP-NOW, sniffing, capture & replay (≈50 min)

- ESP-NOW as a protocol: connectionless 2.4 GHz vendor-action frames, no
  association, optional (here unused) encryption, **no replay protection**.
- Promiscuous-mode capture: how the ESP8266 hears every frame on a channel.
- Finding the channel; reading the swarm's frames ([`protocol.md`](protocol.md)).
- Capture → decode → identify the manipulable fields → the idea of replay.
- The attack taxonomy they'll use: **replay, spoofing, flooding, MITM-style
  manipulation** — map each to a plausible real-world analogue.

Break (~10 min).

## Part 3 — Hands-on: break the swarm, quietly (≈80 min)

- Flash the board ([`flashing.md`](flashing.md)); confirm capture with `FIND`.
- Work through [`exercises.md`](exercises.md): capture → replay → spoof (crash
  a drone, misdirect the swarm) → flood → manipulate.
- Run **extended missions (~5 min of flying/searching)** so students can watch
  their attacks take effect and persist.
- **The detection game:** the commander ("Doom Guy") reacts aloud and visually
  when he spots manipulation. The objective is to **degrade the mission without
  being flagged.** Loud floods get caught; one patient, plausible forged frame
  that quietly diverts a drone is the gold standard.
- Debrief: which attacks were effective? Which were loud? **How would you
  detect or prevent each one?** — land the defensive lesson: authentication,
  anti-replay/nonces, rate-limiting, plausibility/physics checks, and anomaly
  detection are exactly what Doom Guy is doing.

## Running the wall (facilitator notes)

- Start a mission for each hands-on block; use the extended (~5 min) duration so
  effects are observable. Reset between blocks.
- Keep a sniffer of your own up to show the class the traffic on a projector.
- The swarm resets each mission, so a crashed drone revives on the next run —
  students can retry freely.
