# Flashing your ESP8266 on Kali Linux

## 1. Connect the board — read this first

- Use a **USB-C cable plugged into a USB-A port** on your laptop. The board is
  powered from the **5 V** a USB-A port supplies. A USB-C-to-USB-C cable into a
  laptop's USB-C port often **won't power or enumerate** these boards — if you
  see no serial device, this is the first thing to check.
- Most boards use a **CH340** USB-serial chip. Kali has the `ch341` driver
  built in; plug in and check:

  ```bash
  ls /dev/ttyUSB*        # expect /dev/ttyUSB0
  dmesg | tail           # should show "ch341-uart converter now attached to ttyUSB0"
  sudo usermod -aG dialout "$USER"   # then log out/in, so you don't need sudo for serial
  ```

- **No `/dev/ttyUSB*`?** Wrong cable or port (not 5 V / USB-A), a charge-only
  cable, or the driver didn't bind. Try another USB-A port and a known-good
  data cable.

## 2. Install the tools

```bash
sudo apt update && sudo apt install -y python3-pip pipx picocom
pipx install esptool            # flashing
# optional: full build-from-source toolchain
pipx install platformio
```

(`picocom` / `minicom` are serial monitors; PlatformIO's `pio device monitor`
also works.)

## 3. Flash — pick one path

### A. Prebuilt binary (fastest — no toolchain)

```bash
esptool --port /dev/ttyUSB0 --baud 115200 write_flash 0x0 \
  firmware/prebuilt/flockinator-sniffer-esp8266.bin
```

If flashing fails, hold the board's **FLASH/GPIO0** button during the first
second, or drop to `--baud 115200` (slower but more reliable on long cables).

### B. Build from source with PlatformIO

```bash
cd firmware
pio run -t upload            # compiles and flashes
```

### C. Browser (no install) — ESP Web Tools

Open the project's web flasher page in **Chrome/Edge** (WebSerial), pick the
serial port, and flash the prebuilt `.bin`. (Facilitators: host the static
flasher or point students at it.)

## 4. Open the serial monitor

```bash
picocom -b 115200 /dev/ttyUSB0      # exit: Ctrl-A Ctrl-X
# or:  pio device monitor -b 115200
```

On boot you'll see a JSON line like `{"boot":"flock-combined","fw":"...","mode":"sniff"}`.
Type `HELP` and press Enter for the command list. You're ready —
go to [`exercises.md`](exercises.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| No `/dev/ttyUSB*` | USB-A port + data cable (5 V); check `dmesg` |
| `Permission denied` on the port | add yourself to `dialout`, re-login (or `sudo`) |
| Flash timeout / won't sync | hold GPIO0 during connect; lower baud; reseat cable |
| Garbage in the monitor | baud must be **115200** |
| OLED blank but serial works | OLED is optional; the serial JSON is the source of truth |
