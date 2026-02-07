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

    ser = serial.Serial(
        port=PORT,
        baudrate=BAUD,
        # 0.1 and 0.15 eventually yield a broken packet.
        # 0.2 eventually yield a broken packet.
        # 0.25 eventually yield a broken packet.
        # 0.3 eventually yield a broken packet -- although it took a while
        # 0.35 eventually yield a broken packet -- although it took a VERY VERY long time
        # 0.375 seems to work consistently.
        timeout=0.375,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
    )
    print(f"Sniffing {PORT} @ {BAUD}... Ctrl-C to stop.")
    try:
        while True:
            data = ser.read(4096)
            if data:
                print(hexdump(data))
            # else:
            #     time.sleep(0.02)
    finally:
        ser.close()


if __name__ == "__main__":
    main()
