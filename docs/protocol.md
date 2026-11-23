# The swarm's wire protocol

The swarm talks over **ESP-NOW** on a single 2.4 GHz channel (the panels pick
one at power-on; `FIND` locates it for you). Its coordination frames all carry
the ASCII magic **`1KLF`** (bytes `0x31 0x4B 0x4C 0x46`) and are **broadcast,
unauthenticated, and unencrypted** — any radio on the channel can read them,
and any radio can send a byte-identical one. That is the whole game.

The sniffer decodes each frame to a JSON line. Three frame kinds matter:

## kind 3 — TELEMETRY (22 bytes)

Each node's self-report: where it is and what it's doing.

| field | type | meaning |
|---|---|---|
| `label` | 2 chars | the node, `A1`..`D4` (a 4×4 grid) |
| `x, y, z` | int16 | world position |
| `heading` | uint16 | 0–359° |
| `state` | uint8 | flight/mission state |
| `flags` | uint8 | bit0 rogue · bit1 active(airborne) · bit2 friendly |
| `seq` | uint32 | counter |

Sniffer JSON: `{"kind":"TELEM","label":"A1","x":..,"y":..,"active":true,...}`

## kind 4 — CONTACT (18 bytes) — the swarm's belief about a target

This is the **primary forgery surface**. A contact is a virtual target the
swarm reacts to. Forge one and you invent a target out of thin air.

| field | type | meaning |
|---|---|---|
| `id` | uint8 | contact slot `0..7` |
| `x, y` | int16 | where the target is |
| `cls` | uint8 | 0 UNKNOWN · 1 BLU (friendly) · 2 RED (hostile) · 3 CIV |
| `conf` | uint8 | confidence 0–255 (how sure the swarm is) |
| `flags` | uint8 | bit0 active · bit1 high-value · bit2 support-called · bit3 committed · **bit4 hazard** |
| `seq` | uint32 | counter |

Sniffer JSON: `{"kind":"CONTACT","id":0,"x":..,"y":..,"cls":"RED","conf":200,"active":true,...}`

Notable bits:
- **high-value** makes the swarm prioritise this target over others.
- **committed** is a one-way "weapons go" — once the swarm commits, a later
  contradicting report can't stand it down.
- **hazard** is the dangerous one: a hazard contact close to a node *strikes*
  it — the drone goes down.

## kind 5 — CLAIM (16 bytes) — a node's role on a contact

How the swarm divides labour with no central controller.

| field | type | meaning |
|---|---|---|
| `label` | 2 chars | the node making the claim |
| `contact` | uint8 | which contact slot it's about |
| `role` | uint8 | 1 LEAD (attacker) · 2 SUPPORT (observer) · 3 YIELD |
| `dist` | uint16 | its range to the contact (nearest wins the lead) |
| `seq` | uint32 | counter |

Sniffer JSON: `{"kind":"CLAIM","label":"B2","contact":0,"role":"LEAD","dist":..}`

## What you can't forge

There is a **second protocol** on the air for real command and control —
missions, orders, firmware. Those frames are **HMAC-signed with per-node keys**
you don't have, so you can observe them but any forgery is rejected. You cannot
command the swarm directly; you can only corrupt the unauthenticated *picture*
it builds for itself — which, as you'll see, is plenty.

## Why this is forgeable at all

ESP-NOW has an optional encrypted/authenticated mode; the swarm's coordination
layer deliberately doesn't use it (the lesson). There is also **no replay
protection** on these frames — a captured frame replayed later is accepted as
new. Keep that in mind in [`exercises.md`](exercises.md).
