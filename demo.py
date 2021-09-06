
from crcbeagle import crcbeagle

crcb = crcbeagle.CRCBeagle()

#Example 1 - CRC16 with non-standard xor output

crcb.search([[165,  16,  2,  7,  85,  163,  209,  114,  21,  131,  143,  144,  52,  187,  183,  142,  180,  39,  169,  76],
            [165,  16,  2,  7,  140,  39,  242,  202,  181,  209,  220,  248,  156,  112,  66,  128,  236,  187,  35,  176],
            [165,  16,  2,  7,  113,  105,  30,  118,  164,  96,  43,  198,  84,  170,  123,  76,  107,  225,  133,  194]],
            
           [[253,  14],
            [90,  38],
            [248,  236]]
)

crcb = crcbeagle.CRCBeagle()

#Example 2 - linear checksum when you think it might be a CRC8

crcb.search([[0x00, 0xF0, 0x54, 0x01, 0x84, 0x99],
             [0x00, 0xF0, 0x2E, 0x01, 0x0A, 0x40]],

             [[0x9D], [0x96]]
)