# DQ250 MQB Bench Flash Tool

Bench flashing and raw memory dump tool for DQ250 MQB DSG transmission
control units (TCUs) over CAN.

The tool holds the TCU in SBOOT, authenticates through a weak RSA-1024
verification implementation, uploads a small TriCore Flash Manager, and then
reads or programs PFlash and internal DFlash directly. It can also read the
DQ250's external serial EEPROM through the TC1766 SSC0/SPI peripheral.

Credits: [bri3d](https://github.com/bri3d) for the exploit and research hints.

## Important: entering SBOOT

The SBOOT window immediately after power-on is very short.

For a manual start:

1. Connect permanent 12 V, ground, CAN-H and CAN-L to the TCU.
2. Leave ignition/switched positive (`Zündungsplus`, terminal 15) disconnected.
3. Start the desired command.
4. When the tool displays `Power cycle the ECU now, then press ENTER...`,
   connect ignition positive and press `ENTER` immediately.

Connecting ignition positive and pressing `ENTER` must happen very quickly.
If the timing is missed, disconnect ignition positive and try again. A relay
controlled through `--relay-gpio` is strongly recommended because it performs
the power cycle with repeatable timing.

Use a suitable relay module or driver stage. Do not power the TCU or a bare
relay coil directly from a Raspberry Pi GPIO.

## Requirements

- Linux with SocketCAN
- Python 3.10 or newer
- `gmpy2`
- CAN interface configured as `can0` by default
- Bench-connected DQ250 MQB TCU
- Stable 12 V power supply and a common ground between TCU and CAN interface

On Raspberry Pi OS, the software dependencies can be installed with:

```bash
sudo apt update
sudo apt install can-utils python3-gmpy2 net-tools
```

## Raspberry Pi with Waveshare 2-CH CAN FD HAT

The Waveshare 2-CH CAN FD HAT uses two MCP251xFD-compatible CAN controllers
connected through SPI.

### 1. Enable SPI

Run:

```bash
sudo raspi-config
```

Enable SPI under **Interface Options**, then exit `raspi-config`.

### 2. Configure the overlays

Add the following lines to `/boot/firmware/config.txt`:

```ini
dtparam=spi=on
dtoverlay=spi1-3cs
dtoverlay=mcp251xfd,spi0-0,interrupt=25
dtoverlay=mcp251xfd,spi1-0,interrupt=24
```

Reboot the Raspberry Pi:

```bash
sudo reboot
```

### 3. Bring up CAN

Run these commands after every reboot:

```bash
sudo ip link set can0 up type can bitrate 500000
sudo ifconfig can0 txqueuelen 65536
```

The queue length can alternatively be set with the modern `ip` command:

```bash
sudo ip link set can0 txqueuelen 65536
```

Check the interface:

```bash
ip -details link show can0
```

To use the HAT's second channel, bring up `can1` in the same way and pass
`--can can1` to the tool.

## Quick start

All examples use a relay connected to GPIO 17. Remove `--relay-gpio 17` to
use the manual ignition-positive sequence described above.

### Flash ASW and CAL

```bash
python3 dq250_bench_flash.py flash \
  --bin 0D9300042M.bin \
  --blocks ASW CAL \
  --relay-gpio 17
```

### Dump PFlash

```bash
python3 dq250_bench_flash.py dump \
  --out pflash_dump.bin \
  --relay-gpio 17
```

### Dump EEPROM

This reads the external 8 KB SPI EEPROM used by the DQ250 application:

```bash
python3 dq250_bench_flash.py eeprom-dump \
  --out eeprom.bin \
  --relay-gpio 17
```

The command refuses to save a dump containing only `0x00` or only `0xFF`.
Use `--size 0xC00` to read only the area mirrored by the application instead
of the default full 8 KB image.

External EEPROM writing is temporarily disabled until the new SPI read path
has been validated on hardware. This prevents the old implementation from
mistaking internal DFlash for the external EEPROM.

### Dump internal DFlash

```bash
python3 dq250_bench_flash.py dflash-dump \
  --out internal_dflash.bin \
  --relay-gpio 17
```

Internal DFlash may legitimately contain only zeroes on this TCU.

## Additional commands

### Test SBOOT authentication and Flash Manager upload

```bash
python3 dq250_bench_flash.py flash \
  --bin 0D9300042M.bin \
  --ping-only
```

### Read an arbitrary address

```bash
python3 dq250_bench_flash.py flash \
  --bin 0D9300042M.bin \
  --ping-only \
  --read-addr 0xA0020000 \
  --read-len 512
```

### Use another CAN interface

```bash
python3 dq250_bench_flash.py eeprom-dump \
  --out eeprom.bin \
  --can can1 \
  --relay-gpio 17
```

Add `-v` or `--verbose` to any command for detailed logging.

## EEPROM and internal DFlash

The DQ250 application stores its non-volatile records in an external SPI
EEPROM connected to SSC0. The application firmware reads `0xC00` bytes into
its RAM mirror at startup. Bench tools commonly use an 8 KB raw image, which
is therefore the default for `eeprom-dump`.

Separately, the TC1766 contains two internal 16 KB DFlash banks.
`dflash-dump` stores these as one raw 32 KB file with bank 0 followed directly
by bank 1:

| File offset | Size | TCU address |
|-------------|------|-------------|
| `0x0000` | 16 KB | `0xAFE00000` (bank 0) |
| `0x4000` | 16 KB | `0xAFE10000` (bank 1) |

Internal DFlash flashing is available explicitly as `dflash-flash`:

```bash
python3 dq250_bench_flash.py dflash-flash \
  --in internal_dflash.bin \
  --driver-bin 0D9300042M.bin \
  --backup-out dflash-before-flash.bin \
  --relay-gpio 17
```

- both 16 KB banks are read before erasing;
- `--backup-out` saves that pre-flash read;
- an identical input is not rewritten, avoiding unnecessary DFlash wear;
- each bank is erased separately;
- data is programmed in 128-byte pages;
- the complete EEPROM is read back and compared byte-for-byte.

`--driver-bin` must point to a compatible 1.5 MB DQ250 firmware binary. The
tool checks the DRIVER entry-point layout before allowing an erase.

## PFlash binary format

The `flash` command expects a 1.5 MB (`0x180000`) binary:

| Block | File offset | Size | Flash address |
|-------|-------------|------|---------------|
| DRIVER | `0x00000` | `0x80E` | RAM only |
| CAL | `0x30000` | `0x20000` | `0xA0020000` |
| ASW | `0x50000` | `0x130000` | `0xA0040000` |

ASW and CAL must contain valid JAMCRC checksums in their final four bytes.
SBOOT checks these checksums on every boot.

## Command options

### Common options

| Option | Description |
|--------|-------------|
| `--can` | SocketCAN interface; default: `can0` |
| `--relay-gpio` | GPIO controlling the automatic power-cycle relay |
| `--power-off-time` | Relay power-off duration in seconds; default: `2.0` |
| `-v`, `--verbose` | Enable detailed logging |

### PFlash options

| Option | Description |
|--------|-------------|
| `--bin` | DQ250 1.5 MB firmware binary |
| `--blocks` | Blocks to flash: `ASW`, `CAL` or `DRIVER` |
| `--ping-only` | Authenticate and upload the Flash Manager without flashing |
| `--read-addr` | Address to read, for example `0xA0020000` |
| `--read-len` | Number of bytes to read; default: `256` |
| `--skip-erase` | Skip PFlash erase; use only when the flash is already erased |

### EEPROM options

| Option | Description |
|--------|-------------|
| `--out` | EEPROM dump output path |
| `--size` | Bytes to read; default: `0x2000` (8 KB), application mirror: `0xC00` |

### Internal DFlash options

| Option | Description |
|--------|-------------|
| `--in` | Raw 32 KB internal DFlash image to flash |
| `--driver-bin` | Compatible 1.5 MB binary supplying the DRIVER |
| `--backup-out` | Save the current DFlash before erasing |
| `--yes` | Skip the `FLASH` confirmation prompt |

## How it works

### SBOOT hold and authentication

On power-up the TCU normally runs SBOOT → CBOOT → ASW. Repeated requests on
CAN ID `0x640` keep SBOOT in its command loop. The tool then advances through
the internal authentication phases and forges the required RSA signatures by
exploiting SBOOT's relaxed PKCS#1 v1.5 verification.

### Flash Manager upload

The tool uploads TriCore code to PSPR RAM at `0xD4000000`. For write
operations, the payload includes the firmware's DRIVER routines. The Flash
Manager then communicates through raw eight-byte CAN frames:

| Command | ID | Description | Response |
|---------|----|-------------|----------|
| PING | `0x01` | Alive check | `0x41` + `DQ250` |
| READ | `0x02` | Read four bytes per frame | `0x42` + data |
| ERASE | `0x03` | Erase one flash sector | `0x43` + status |
| WRITE_START | `0x04` | Set target address and length | `0x44` |
| WRITE_DATA | `0x05` | Stream four data bytes per frame | `0x45` |
| VERIFY | `0x06` | Return write verification state | `0x46` |
| FLASH_RESET | `0x07` | Reset the flash state machine | `0x47` |
| EEPROM_READ | `0x08` | Read external EEPROM through SSC0/SPI | `0x48` + data |
| RESET | `0xFF` | Set warm-boot state and reset the TCU | none |

After a PFlash operation, the reset command writes the CBOOT warm-boot magic,
triggers an application reset, and allows the validated ASW to start.

## Hardware reference

### TC1766 memory

- PFlash0: `0xA0000000`–`0xA00FFFFF`
- PFlash1 used range: `0xA0100000`–`0xA016FFFF`
- DFlash bank 0: `0xAFE00000`–`0xAFE03FFF`
- DFlash bank 1: `0xAFE10000`–`0xAFE13FFF`
- PSPR RAM: `0xD4000000`–`0xD4003FFF`
- DSPR RAM: `0xD0000000`–`0xD000FFFF`

### CAN IDs

| ID | Direction | Description |
|----|-----------|-------------|
| `0x640` | Host → TCU | SBOOT and Flash Manager request |
| `0x641` | TCU → Host | SBOOT and Flash Manager response |
| `0x7E1` | Host → TCU | CBOOT UDS request |
| `0x7E9` | TCU → Host | CBOOT UDS response |
