# CRC Beagle

CRC Beagle is a tool for reverse engineering CRCs. It is designed for commnication protocols where you often have several messages of the same length. This allows CRC Beagle to use the CRC Differential Technique described by Method by Gregory Ewing described in [Reverse-Engineering a CRC Algorithm](http://www.cosc.canterbury.ac.nz/greg.ewing/essays/CRC-Reverse-Engineering.html)

The advantage of this technique is it allows recovery of an "effective equivalent" CRC even in cases where the algorithm uses non-standard parameters for XOR-in or XOR-out (a common obfuscation technique).

The [CRC RevEng tool by Greg Cook](https://reveng.sourceforge.io/) is a more mature tool, I haven't implemented as much. I started CRC Beagle to (a) use Python which I find much easier to modify, and (b) when CRC RevEng failed to recover a CRC for a device I was looking at, and it was difficult to understand why.

CRC Beagle has some other handy features, such as giving you the code you need to create valid CRCs with a copy-paste. It also checks inputs when running on 8-bit CRCs to see if it's just a simple checksum and not a real CRC.

Hopefully you find CRC Beagle useful, but this is hardly a novel creation, so the credit goes to those who built up the foundation.

## Using CRC Beagle

The basic usage is shown in the file `demo.py`:

```
from crcbeagle import crcbeagle

crcb = crcbeagle.CRCBeagle()

crcb.search([[165,  16,  2,  7,  85,  163,  209,  114,  21,  131,  143,  144,  52,  187,  183,  142,  180,  39,  169,  76],
        [165,  16,  2,  7,  140,  39,  242,  202,  181,  209,  220,  248,  156,  112,  66,  128,  236,  187,  35,  176],
        [165,  16,  2,  7,  113,  105,  30,  118,  164,  96,  43,  198,  84,  170,  123,  76,  107,  225,  133,  194]],
        
       [[253,  14],
        [90,  38],
        [248,  236]]
)
```

This generates an output like this:

```
Input parameters:
    16-bit CRC size
    3 total messages, with:
       3 messages with 20 byte payload
NOTE: Output parameters will be specific to this message size only. Pass different length messages if possible.

Working on messages of 20 length:
  Found single likely solution for differences of len=20, yah!
  Found single XOR-out value for len = 20: 0xCACA
********** example usage *************
import struct
from crccheck.crc import Crc16Base
crc = Crc16Base
def my_crc(message):
  crc._poly = 0x1021
  crc._reflect_input = False
  crc._reflect_output = False
  crc._initvalue = 0x0
  crc._xor_output = 0xCACA
  output_int = crc.calc(message)
  output_bytes = struct.pack("<H", output_int)
  output_list = list(output_bytes)
  return (output_int, output_bytes, output_list)

m = [165, 16, 2, 7, 85, 163, 209, 114, 21, 131, 143, 144, 52, 187, 183, 142, 180, 39, 169, 76]
output = my_crc(m)
print(hex(output[0]))
**************************************
If you have multiple message lengths this solution may be valid for this only.
```

## Important Limitations

The CRC differential technique packs all of the "constant bytes" into the  XOR-out parameters.

Constants that occur at the start of the CRC are transformed by the CRC operation. This transformation depends on the number of cyclic shifts - that means the constant *changes* for different lengths of messages, since the number of cyclic shifts changes every time you 'add' a byte to the CRC.

If you can find the 'actual' XOR-in settings, or how many bytes the operation takes, you will have a more generic function.

However in practice I find that many communication protocols only transmit certain length messages. Thus having different XOR-out values for each message length isn't a major problem for the purpose of interoperating with the original system.

This tool doesn't try to be too clever and just spits out settings for each message length you gave it.

## How it Works

