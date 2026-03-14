# DQ250 MQB Bench Flash Tool

Bench flashing tool for DQ250 MQB DSG transmission control units (TCU) over CAN.

Exploits a weakness in SBOOT (Bleichenbacher RSA e=3 forge) to flash the TCU directly on the bench without OEM diagnostic software.

## Requirements

- Linux with SocketCAN (`can0`)
- Python 3.10+
- `gmpy2` (`pip install gmpy2`)
- CAN interface (e.g. PCAN-USB, Kvaser, MCP2515)
- DQ250 MQB TCU on bench (12V supply, CAN-H/CAN-L)

## Process

### 1. Holding SBOOT session

On power-up the TCU goes through: SBOOT → CBOOT → ASW. By spamming CAN frames on `0x640` during the boot window, SBOOT is kept in its main loop and never jumps to CBOOT/ASW.

### 2. SBOOT authentication

SBOOT implements a phase-gated UDS-like protocol:

| Phase | Service | Description |
|-------|---------|------------|
| 1→2 | `1A 8F` | Set internal flag |
| 2→3 | `1A 8A` | Read data |
| 3→4 | `1A 8B` | Unlock SA |
| 4→6 | `27 FD/FE` | RSA-1024 authentication (Bleichenbacher forge, e=3) |

SBOOT's RSA verification has two flaws:
- Padding bytes are only checked for `!= 0x00` (not `== 0xFF`)
- Nothing is verified after the hash (trailing garbage ignored)

With e=3, a valid signature can be computed via cube root (~2-5 seconds).

### 3. Shellcode upload

After authentication, a **Flash Manager** is uploaded as TriCore shellcode to PSPR RAM (`0xD4000000`):

| Offset | Content | Size |
|--------|---------|------|
| `0x000` | DRIVER block (erase/write/verify routines from bin) | ~2 KB |
| `0x900` | Flash Manager (CAN command loop) | ~1.1 KB |
| after FM | Param struct + data buffer | remainder |

The upload is also signed via Bleichenbacher forge (second RSA key for code verification).

### 4. Flash Manager protocol

The Flash Manager runs as a polling loop in PSPR and communicates via raw CAN frames (no ISO-TP):

| Cmd | ID | Description | Response |
|-----|----|------------|----------|
| `0x01` | PING | Alive check | `0x41` + "DQ250" |
| `0x02` | READ | Read flash (4 bytes/frame) | `0x42` + data |
| `0x03` | ERASE | Erase flash sector | `0x43` + status |
| `0x04` | WRITE_START | Set write target (addr + len) | `0x44` |
| `0x05` | WRITE_DATA | Stream data (4 bytes/frame) | `0x45` (every 64 frames) |
| `0x06` | VERIFY | Verification (already done during write) | `0x46` |
| `0x07` | FLASH_RESET | Reset flash state machine | `0x47` |
| `0xFF` | RESET | Write warm boot magic + application reset | — |

Addresses and lengths are transmitted as little-endian in CAN frames.

### 5. Flashing

For each block (ASW, CAL):
1. **Erase** — Erase all affected sectors (DRIVER `0x204`)
2. **Write** — Write data page-by-page (256 bytes) with verify (DRIVER `0x334`)
3. **Verify** — Confirmation

### 6. Reset

The RESET command writes CBOOT warm boot magic to DSPR:
- `0xD000DFFC` = `0x5353015B`
- `0xD000DFF8` = `0xACACFEA4`
- `0xD000DFF4` = `0x25A5A5A2` (programming complete)

Then triggers an application reset via `SCU_RSTCON`. CBOOT recognizes the magic, validates CRC, clears sticky NVM error flags, and boots the new ASW.

## Binary format

Expects a 1.5 MB (0x180000) binary with the following layout:

| Block | Offset | Size | Flash address |
|-------|--------|------|---------------|
| DRIVER | `0x00000` | 0x80E | — (RAM only) |
| CAL | `0x30000` | 0x20000 | `0xA0020000` |
| ASW | `0x50000` | 0x130000 | `0xA0040000` |

ASW and CAL must have valid JAMCRC checksums in the last 4 bytes (SBOOT checks on every boot).

## Usage

### Flashing

```bash
# Flash all blocks (relay on GPIO 17 for power cycle)
python3 dq250_bench_flash.py flash --bin 0D9300042M.bin --blocks ASW CAL --relay-gpio 17

# Manual power cycle (no relay)
python3 dq250_bench_flash.py flash --bin 0D9300042M.bin --blocks ASW CAL

# PING test only (no flash)
python3 dq250_bench_flash.py flash --bin 0D9300042M.bin --ping-only

# Read flash memory
python3 dq250_bench_flash.py flash --bin 0D9300042M.bin --ping-only --read-addr 0xA0020000 --read-len 512

# Verbose output
python3 dq250_bench_flash.py flash --bin 0D9300042M.bin --blocks ASW CAL -v
```

### Full dump

```bash
# Dump entire PFlash (1.5 MB)
python3 dq250_bench_flash.py dump --out pflash_dump.bin --relay-gpio 17
```

### Options

| Option | Description |
|--------|------------|
| `--bin` | DQ250 binary file (1.5 MB) |
| `--blocks` | Blocks to flash: `ASW`, `CAL` (default: all) |
| `--can` | CAN interface (default: `can0`) |
| `--relay-gpio` | GPIO pin for relay power cycle |
| `--ping-only` | SBOOT auth + PING only, no flash |
| `--read-addr` | Address to read (hex) |
| `--read-len` | Bytes to read (default: 256) |
| `--skip-erase` | Skip erase step (when flash is already erased) |
| `-v` | Verbose/debug output |

## Hardware

### TC1766 (TriCore)

- PFlash0: `0xA0000000` – `0xA00FFFFF` (1 MB)
- PFlash1: `0xA0100000` – `0xA016FFFF` (448 KB used)
- PSPR RAM: `0xD4000000` – `0xD4003FFF` (16 KB) — shellcode target
- DSPR RAM: `0xD0000000` – `0xD000FFFF` (64 KB)

### CAN IDs

| ID | Direction | Description |
|----|-----------|------------|
| `0x640` | Host → TCU | SBOOT/FM requests |
| `0x641` | TCU → Host | SBOOT/FM responses |
| `0x7E1` | Host → TCU | CBOOT UDS (standard) |
| `0x7E9` | TCU → Host | CBOOT UDS response |
