#!/usr/bin/env python3
import binascii
import serial
import time

PORT = "/dev/ttyUSB0"
BAUD = 9600

def hexdump(b: bytes) -> str:
    return binascii.hexlify(b, b" ").decode()

def main():
    print("Hello from fuzz!")

    ser = serial.Serial(PORT, BAUD, timeout=0.1)
    print(f"Sniffing {PORT} @ {BAUD}... Ctrl-C to stop.")
    try:
        while True:
            data = ser.read(4096)
            if data:
                print(hexdump(data))
            else:
                time.sleep(0.02)
    finally:
        ser.close()


if __name__ == "__main__":
    main()
