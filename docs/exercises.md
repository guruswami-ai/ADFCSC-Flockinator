# Exercises: capture, decode, and attack the swarm

Your weapon is one ESP8266 running the combined **sniffer + injector**. It has
two modes — **SNIFF** (listen) and **INJECT** (transmit) — because one radio
can't do both at once. It boots in SNIFF.

## The tool — serial command reference (115200 baud)

| command | mode | what it does |
|---|---|---|
| `FIND` | sniff | scan the band, lock onto the swarm's channel |
| `SCAN` | sniff | scan but stay on your current channel (just report) |
| `CH <1-13>` | any | tune to a channel manually |
| `SNIFF` / `INJECT` | any | switch mode (any inject command auto-switches to INJECT) |
| `STATS` | any | counters: frames seen, injected, per kind |
| `VERBOSE` / `QUIET` | sniff | turn the per-frame JSON stream on/off |
| `CONTACT <id> <x> <y> <cls> <conf> <flags>` | inject | forge a target contact (kind 4) |
| `CLAIM <label> <contact> <role> <dist>` | inject | forge a role claim (kind 5) |
| `SEND <hex>` | inject | transmit one raw frame (bytes as hex) — your replay primitive |
| `CONTACT <id> OFF` / `CLAIM <label> OFF` | inject | stop re-sending that forged frame |

`cls`: 0 UNKNOWN, 1 BLU, 2 RED, 3 CIV. `role`: 1 LEAD, 2 SUPPORT, 3 YIELD.
`flags` is a number — add the bits: 1 active, 2 high-value, 8 committed, **16 hazard**.
(See [`protocol.md`](protocol.md).)

---

## Exercise 1 — Capture & decode

1. `FIND`. When it locks, you'll see JSON frames streaming.
2. Watch `TELEM` (the drones' positions), `CONTACT` (targets), `CLAIM` (roles).
3. `STATS` to see rates. `QUIET` to stop the stream, `VERBOSE` to resume.

> **Goal:** read the swarm's mind. Which nodes are flying? Is there a target
> up? Who's the LEAD on it?

## Exercise 2 — Replay

Capture a real frame and send it back, out of its original context.

1. In SNIFF, copy a frame's raw hex (the sniffer prints it with `VERBOSE` /
   the `RAW` dump).
2. `SEND <hex>` to retransmit it. There's no replay protection — the swarm
   takes it as fresh.

> **Try:** replay an old CONTACT after the real target is gone — does the swarm
> keep chasing a ghost?

## Exercise 3 — Spoofing (forge false data)

Invent targets and roles that were never there.

- **Misdirect:** `CONTACT 0 <x> <y> 2 200 1` — a fake RED target. The nodes
  that take it on will **steer toward it**. Put it somewhere useless and you've
  pulled attackers off the real mission to a decoy.
- **Crash a drone:** `CONTACT 0 <x> <y> 2 255 17` — `17` = active + hazard. A
  hazard contact on top of a drone **strikes it out of the sky.** Read a node's
  `TELEM` position first, then drop the hazard there.
- **Role confusion:** forge `CLAIM`s so several nodes think they're LEAD, or
  make the real LEAD `YIELD`. Watch the swarm argue with itself.
- **Hijack priority:** a `high-value` (`flags` +2) or `committed` (+8) contact
  outranks everything — the whole swarm pivots to your invented target.

## Exercise 4 — Flooding

Inject fast and often — many contacts, rapid re-sends, contradictory claims.
Can you overwhelm the swarm's picture so it can't settle on anything? Note the
cost: floods are **loud** (see Detection, below).

## Exercise 5 — Manipulation / MITM-style

True man-in-the-middle is hard on a broadcast medium — you can't silently sit
between two nodes. But you can get the same effect: **observe a real frame,
then immediately transmit a louder, altered copy** so your version wins. Flip a
contact's class (RED→CIV to call off an attack, or CIV→RED to start one), or
walk a target's position a few units each frame so a drone chases it off course.

---

## Your mission: degrade theirs — quietly

Your objective is to **degrade the swarm's missions** — divert it, crash
drones, stall its decisions. But there's a catch:

> **The commander is listening.** "Doom Guy" watches the real traffic and
> **calls out, aloud and on his face,** whenever he spots something wrong:
> telemetry that teleports, confidence that flip-flops, a flood of frames, two
> nodes both claiming LEAD, or a drone doing something nobody ordered.

So the real challenge isn't *can* you break the swarm — it's whether you can do
it **without being detected.** Brute flooding works but gets you spotted
instantly. A single, plausible, well-timed forged frame that quietly sends one
drone to the wrong place — that's the win. Minimal, realistic, patient.

Think like the defender you're learning to be: every attack you land is a
detection signature someone could have caught.
