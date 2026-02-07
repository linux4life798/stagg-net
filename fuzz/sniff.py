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
        # 0.1 and 0.15 eventually yield a broken packet -- after 13, 20, 36, or 44 packets
        # 0.2 eventually yield a broken packet.
        # 0.25 eventually yield a broken packet -- after 72 or 99 packets
        # 0.3 eventually yield a broken packet -- although it took a while
        # 0.35 eventually yield a broken packet -- although it took a VERY VERY long time
        # 0.375 eventually yield a broken packet -- although it took a VERY long time -- 73 packets (x 3 seconds between packets)
        # 0.4 eventually yield a broken packet -- although it took a VERY long time -- 89 packets (x 3 seconds between packets)
        # 0.??? seems to work consistently.
        timeout=0.25,
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
