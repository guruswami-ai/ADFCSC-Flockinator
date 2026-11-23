# Sanitization report

This repo is intended for **public** release and was assembled from a private
project. Before it is published, it was checked for internal/sensitive data.

## Scrubbed
- Internal source-path references in firmware code comments (e.g. paths into the
  private node/controller trees) rewritten to generic descriptions.
- No deploy, controller, firewall, Wi-Fi, 1Password, or key material was copied
  in — only the student-facing sniffer+injector firmware and freshly written
  docs.

## Denylist (verified absent across the whole repo)
Wi-Fi SSID/password; `10.61.106.x` and any internal IPs; device MAC addresses;
hostnames of internal machines; `op://` / 1Password, Kathaka, OPNsense; the
HMAC `/v1` maintenance interface and per-node keys; DHCP/reservation details.
A recursive grep for these terms returns empty (see commit). The `docs/handbook/`
HTML, SVG screen renders, and compiled PDF were added afterwards and re-scanned clean.

## What's intentionally included (it's the exercise)
- The **FLK1** unauthenticated frame formats students sniff and forge.
- ESP-NOW channel scanning (`FIND`) — students locate the channel themselves.
- The **FLK2** authenticated layer is mentioned only as "HMAC-signed, not
  forgeable"; no keys or signing details are included.

## A human must do before publishing
1. Re-run a full secrets scan (e.g. `gitleaks`/`trufflehog`) on the repo.
2. Confirm the prebuilt `firmware/prebuilt/*.bin` is the intended build.
3. ~~Add the ESP Web Tools browser-flasher page.~~ **Done** — `docs/handbook/flasher/`
   (ESP Web Tools vendored unmodified, Apache-2.0, see `NOTICE.md`).
4. Decide the public remote and push (this repo has **no remote** configured).
