# Info

* **WARNING: +5VDC ping seems to be very low resistance to the hot side of mains power in.**
  Furthermore, you can see 5V DC potential across line/main's hot lead and 0V DC.
  At the very least, you should not connect the +5V DC to your laptop's serial
  to USB adapter.
* The internal serial connector, intended for the optional Bluetooth module,
  operates at 3.3V and 9600 baud.
* It appears to have 1 start bit.
* It sends some kind of status message every 3 seconds.


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
