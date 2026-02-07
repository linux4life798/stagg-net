#!/usr/bin/env python3
import binascii
import serial
import time

PORT = "/dev/ttyUSB0"
BAUD = 9600

# The magic init sequence (in hex) used to authenticate with the kettle:
# ef dd 0b 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 9a 6d
INIT_SEQUENCE = bytes.fromhex("efdd0b3031323334353637383930313233349a6d")
INIT_SEQUENCE2 = bytes.fromhex("ef0b3031323334353637383930313233349a6d")

TEST1 = bytes.fromhex("efdd")

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
        # inter_byte_timeout=0.01,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
    )
    print(f"Sniffing {PORT} @ {BAUD}... Ctrl-C to stop.")

    # 46 65 6c 6c 6f 77 3a 20 72 65 73 65 74 5f 63 6f 6e 74 72 6f 6c 6c 65 72 0a
    # startup = b"Follow: reset_controller\n"

    try:
        ser.write(INIT_SEQUENCE)
        # ser.write(INIT_SEQUENCE2)
        while True:
            # ser.write(bytes([i, j, 0x0A]))
            # ser.write(INIT_SEQUENCE)
            data = ser.read(4096)
            if data:
                print(hexdump(data))
            # else:
            #     time.sleep(0.02)
    finally:
        ser.close()


if __name__ == "__main__":
    main()
