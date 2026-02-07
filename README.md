# Info

* **WARNING: +5VDC ping seems to be very low resistance to the hot side of mains power in.**
  Furthermore, you can see 5V DC potential across line/main's hot lead and 0V DC.
  At the very least, you should not connect the +5V DC to your laptop's serial
  to USB adapter.
* The internal serial connector, intended for the optional Bluetooth module,
  operates at 3.3V and 9600 baud.
* It appears to have 1 start bit.
* It sends some kind of status message every 3 seconds.
* The [Stagg EKG+ Manual] mentions `Contains Transmitter - FCC ID: 2AABGBTAC1000`.
* When we search for this FCC ID on FCC.io, https://fcc.io/2AABGBTAC1000,
  we see mention of `EnzyTek Technoloy Inc.` for a part 15C in the 2.4GHz range and a link to the [EnzyTek BTA-C1000-2 Datasheet/Manual].
* From that module datasheet, it appear that the actual Radio MCU is called
  the `CSR CSR1000`. I found the [CSR CSR100 Datasheet].
* Qualcomm acquired CSR (Cambridge Silicon Radio) in 2014.
  Now there is a [Qualcomm CSR101x Series].

![Bottom cover](images/bottom-cover.jpeg)
![Bottom cover removed](images/bottom-cover-removed.jpeg)

[Stagg EKG+ Manual]: https://ep-shopify.s3.amazonaws.com/related-documents/fellow/ekg%2B/stagg-ekg%2B-manual.pdf
[EnzyTek BTA-C1000-2 Datasheet/Manual]: https://fcc.report/FCC-ID/2AABGBTAC1000/1978486.pdf
[CSR CSR100 Datasheet]: https://pdf.dzsc.com/99999/2013328165148606.pdf
[Qualcomm CSR101x Series]: https://www.qualcomm.com/bluetooth/products/csr101x-series#benefits

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
