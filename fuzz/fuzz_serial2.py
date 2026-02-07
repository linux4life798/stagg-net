#!/usr/bin/env python3
import binascii
import time
from pathlib import Path

from boofuzz import (
    Session,
    Target,
    s_initialize,
    s_static,
    s_random,
    s_get,
    s_block,
)
from boofuzz.connections import SerialConnection

PORT = "/dev/ttyUSB0"
BAUD = 9600
READ_TIMEOUT = 0.05           # per read
RESP_WINDOW = 0.30            # total time to collect response after each send
# RESP_WINDOW = 0.3
SLEEP_BETWEEN_TESTS = 0.05

BASELINE = bytes.fromhex("ef 0a 00 ef 0a")

# The magic init sequence (in hex) used to authenticate with the kettle:
# ef dd 0b 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 9a 6d
INIT_SEQUENCE = bytes.fromhex("efdd0b3031323334353637383930313233349a6d")

LOG_PATH = Path("interesting_responses.log")


def hx(b: bytes) -> str:
    return binascii.hexlify(b, b" ").decode()


def strip_baseline(data: bytes) -> bytes:
    """
    Remove all occurrences of the baseline 5-byte heartbeat from a blob.
    This is a blunt but effective first filter.
    """
    if not data:
        return b""
    while True:
        new = data.replace(BASELINE, b"")
        if new == data:
            return new
        data = new


def read_window(target, window_s: float) -> bytes:
    """
    Read whatever the device sends for 'window_s' seconds.
    Accumulate into one buffer.
    """
    end = time.time() + window_s
    out = bytearray()
    while time.time() < end:
        chunk = target.recv(4096)  # uses SerialConnection timeout
        if chunk:
            out += chunk
        else:
            # tiny sleep so we don't busy-loop
            time.sleep(0.005)
    return bytes(out)


def define_requests():
    # 1) Pure random binary, no assumed header
    s_initialize("rand_bin")
    with s_block("msg"):
        s_random(b"", min_length=1, max_length=24, num_mutations=2000, name="blob")

    # 2) Common ASCII probes
    for name, payload in [
        ("ascii_AT", b"AT\r\n"),
        ("ascii_help", b"help\r\n"),
        ("ascii_q", b"?\r\n"),
        ("ascii_status", b"status\r\n"),
        ("ascii_version", b"version\r\n"),
    ]:
        s_initialize(name)
        with s_block("msg"):
            s_static(payload)

    # 3) A few “framed guesses” (including EF 0A, but not only)
    for name, hdr in [
        ("hdr_ef0a", bytes.fromhex("ef 0a")),
        ("hdr_efdd", bytes.fromhex("ef dd")),
        ("hdr_aa55", bytes.fromhex("aa 55")),
        ("hdr_55aa", bytes.fromhex("55 aa")),
        ("hdr_a5",   bytes.fromhex("a5")),
        ("hdr_fe",   bytes.fromhex("fe")),
        ("hdr_ef",   bytes.fromhex("ef")),
        ("init_sequence", INIT_SEQUENCE),
    ]:
        s_initialize(name)
        with s_block("msg"):
            s_static(hdr)
            s_random(b"", min_length=0, max_length=64, num_mutations=1000, name="payload")


def log_interesting(case_name: str, sent: bytes, raw: bytes, filtered: bytes):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"\n=== {case_name} ===\n")
        f.write(f"SENT: {hx(sent)}\n")
        f.write(f"RAW : {hx(raw)}\n")
        f.write(f"FILT: {hx(filtered)}\n")


def main():
    define_requests()

    conn = SerialConnection(port=PORT, baudrate=BAUD, timeout=READ_TIMEOUT)
    target = Target(connection=conn)

    session = Session(
        target=target,
        sleep_time=SLEEP_BETWEEN_TESTS,
        receive_data_after_fuzz=False,  # we'll do our own controlled read window
        session_filename="boofuzz-session.db",
    )

    # Connect all our request definitions
    for name in ["rand_bin", "ascii_AT", "ascii_help", "ascii_q", "ascii_status", "ascii_version",
                 "hdr_ef0a", "hdr_efdd", "hdr_aa55", "hdr_55aa", "hdr_a5", "hdr_fe", "hdr_ef", "init_sequence"]:
        session.connect(s_get(name))

    # Custom fuzz loop so we can access the exact bytes sent
    # boofuzz doesn't hand us "sent bytes" in a super clean way everywhere,
    # so we use the session's built-in mutation engine but intercept target.send.
    orig_send = target.send

    def send_and_classify(data: bytes):
        # Send testcase
        orig_send(data)

        # Read response window
        raw = read_window(target, RESP_WINDOW)
        filtered = strip_baseline(raw)

        # Interesting if: any remaining bytes after stripping baseline
        # OR raw exists but filtered differs (e.g., partial baseline + extra)
        if filtered:
            print("INTERESTING! sent=", hx(data), " resp=", hx(filtered))
            log_interesting("unknown_case", data, raw, filtered)

    target.send = send_and_classify  # monkey patch for quick wins

    session.fuzz()


if __name__ == "__main__":
    main()
