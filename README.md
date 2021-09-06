#CRC Beagle

CRC Beagle is a tool for reverse engineering CRCs. It is designed for commnication protocols where you often have several messages of the same length. This allows CRC Beagle to use the CRC Differential Technique described by Method by Gregory Ewing described in [Reverse-Engineering a CRC Algorithm](http://www.cosc.canterbury.ac.nz/greg.ewing/essays/CRC-Reverse-Engineering.html)

The advantage of this technique is it allows recovery of an "effective equivalent" CRC even in cases where the algorithm uses non-standard parameters for XOR-in or XOR-out (a common obfuscation technique).

The [CRC RevEng tool by Greg Cook](https://reveng.sourceforge.io/) is a more mature tool. I started CRC Beagle to (a) use Python which I find much easier to modify, and (b) when CRC RevEng failed to recover a CRC for a device I was looking at, and it was difficult to understand why.

Hopefully you find CRC Beagle useful, but this is hardly a novel creation, so the credit goes to those who built up the foundation.

## Using CRC Beagle

```
import crcbeagle

crcbeagle.sniff([])
```

## Important Limitations

The CRC differential technique packs all of the "constant bytes" into the XOR-in and XOR-out parameters.

## How it Works

