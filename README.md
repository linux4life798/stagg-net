# Info

* **WARNING: +5VDC ping seems to be very low resistance to the hot side of mains power in.**
  Furthermore, you can see 5V DC potential across line/main's hot lead and 0V DC.
  At the very least, you should not connect the +5V DC to your laptop's serial
  to USB adapter.
* The internal serial connector, intended for the optional Bluetooth module,
  operates at 3.3V and 9600 baud.
* It appears to have 1 start bit.
* It sends some kind of status message every 3 seconds.

![Bottom cover](images/bottom-cover.jpeg)
![Bottom cover removed](images/bottom-cover-removed.jpeg)

# UART Protocol

All I see is that the display module sends the following every 3 seconds.
It does not change based on target temperature set point or on/off state.

```
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
EF 0A 00 EF 0A
```

Upon startup, it transmits the following:

```
46 65 6C 6C 6F 77 3A 20 72 65 73 65 74 5F 63 6F 6E 74 72 6F 6C 6C 65 72
0A EF 0A 00 EF 0A
```

Which spells out `Fellow: reset_controller` on the first line.
