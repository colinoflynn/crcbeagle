#
# CRC Beagle, automatic CRC/Checksum detection for communication protocols.
#
# Copyright (C) Colin O'Flynn, 2021.
#
# See https://github.com/colinoflynn/crcbeagle for more details.
#
# See LICENSE file for distribution requirements.
#
# CRC differential technique based on Gregory Ewing
# https://www.cosc.canterbury.ac.nz/greg.ewing/essays/CRC-Reverse-Engineering.html
#


import logging
import struct

from crccheck.crc import Crc8Base, Crc16Base, Crc32Base, ALLCRCCLASSES

class CRCBeagle(object):
    """
    CRCBeagle searches for matching CRC parameters based on several passed messages.
    described by Gregory Ewing which avoids needing to fully understand the actual
    CRC input settings, which is very useful when reverse engineering communications
    protocols.

    The basic usage is simply to pass 2 to 4 example messages & CRC pairs:
    ```
        crcb = crcbeagle.CRCBeagle()

        crcb.search(
            [[165,  16,  2,  7,  85,  163,  209,  114,  21,  131,  143,  144,  52,  187,  183,  142,  180,  39,  169,  76],
             [165,  16,  2,  7,  140,  39,  242,  202,  181,  209,  220,  248,  156,  112,  66,  128,  236,  187,  35,  176],
             [165,  16,  2,  7,  113,  105,  30,  118,  164,  96,  43,  198,  84,  170,  123,  76,  107,  225,  133,  194]],
            
            [[253,  14],
             [90,  38],
             [248,  236]])
    ```
    """

    def crcdict_to_packstr(self, crcdict):
        """
        Based on the 'crclen' and 'order' fields of `crcdict` returns a string used by
        struct to pack/unpack the CRC.
        """
        crclen = crcdict['crclen']

        if crclen == 1:
            packstr = "B"
        elif crclen == 2:
            if crcdict["order"] == "le":
                packstr = "<H"
            elif crcdict["order"] == "be":
                packstr = ">H"
            else:
                raise ValueError("Invalid 'order': " + crcdict["order"])
        elif crclen == 4:
            if crcdict["order"] == "le":
                packstr = "<I"
            elif crcdict["order"] == "be":
                packstr = ">I"
            else:
                raise ValueError("Invalid 'order': " + crcdict["order"])
        else:
            raise ValueError("Invalid crclen: %d"%crclen)
        
        return packstr

    def str_crc_example(self, crcdict, message=None):
        """
        Generates example code for using the CRC parameters based on `crccheck` library.

        Optional `message` parameter should be a list or bytearray that will be passed to
        the resulting crc function, normally this message would be one of the examples.
        """
        
        crclen = crcdict['crclen']

        packstr = self.crcdict_to_packstr(crcdict)

        example_str = "import struct\n"
        if crclen == 1:
            example_str += "from crccheck.crc import Crc8Base\ncrc = Crc8Base\n"
        elif crclen == 2:
            example_str += "from crccheck.crc import Crc16Base\ncrc = Crc16Base\n"
        else:
            example_str += "from crccheck.crc import Crc32Base\ncrc = Crc32Base\n"
        
        example_str += "def my_crc(message):\n"
        example_str += "  crc._poly = 0x%X\n"%crcdict['poly'] +\
                    "  crc._reflect_input = %r\n"%crcdict['reflectin'] +\
                    "  crc._reflect_output = %r\n"%crcdict['reflectout'] +\
                    "  crc._initvalue = 0x%0X\n"%crcdict['init'] +\
                    "  crc._xor_output = 0x%0X\n"%crcdict['xor_output']

        example_str += "  output_int = crc.calc(message)\n"
        example_str += '  output_bytes = struct.pack("%s", output_int)\n'%packstr
        example_str += "  output_list = list(output_bytes)\n"
        example_str += "  return (output_int, output_bytes, output_list)\n"
        
        if message:
            example_str += "\n"
            example_str += "m = %r\n"%message
            example_str += "output = my_crc(m)\n"
            example_str += "print(hex(output[0]))"
        
        return example_str

    def print_crc_example(self, crcdict, message=None):
        """
        Prints to stdout example code for using the CRC parameters based on `crccheck` library.

        Optional `message` parameter should be a list or bytearray that will be passed to
        the resulting crc function, normally this message would be one of the examples.
        """
        print(self.str_crc_example(crcdict, message))
    
    def validate_inputs(self, messages, crcs):
        """
        Sanity checks input data, such as CRC lengths match. Prints status of
        input parameters for user pleasure.
        """
        
        if len(messages) != len(crcs):
            raise ValueError("Length of message & crc arrays don't match: %d, %d"%(len(messages), len(crcs)))
        
        logging.info("Got %d input message-crc pairs"%len(messages))
        
        #Figure out how many messages are same size
        message_size_dict = {}
        
        for i, m in enumerate(messages):
            l = len(m)
            if l not in message_size_dict.keys():
                message_size_dict[l] = {"num":1, "indexes":[i]}
            else:
                message_size_dict[l]["num"] += 1
                message_size_dict[l]["indexes"].append(i)
        
        #Basic CRC input validation
        crclen = None
        for c in crcs:
            try:
                if crclen is None:
                    crclen = len(c)
                else:
                    if len(c) != crclen:
                        raise ValueError("Expect CRC inputs to be same array length, expected %d, found %d (%s)"%(crclen, len(c), str(c)))
            except TypeError:
                raise TypeError("CRC must be passed as byte list or bytearray, not int")
        
        if crclen != 1 and crclen != 2 and crclen != 4:
            raise("Detected %d-bit CRC, not supported"%(crclen *8))
        
        print("Input parameters:")
        print("    %d-bit CRC size"%(crclen * 8))
        print("    %d total messages, with:"%len(messages))
        for k in message_size_dict.keys():
            print("      %2d messages with %d byte payload"%(message_size_dict[k]["num"], k))
        
        self.message_size_dict = message_size_dict
        self.crclen = crclen
    
    def search_linear(self, messages, crcs, print_examples=True):
        """
        Checks if a simple checksum can provide the required CRC,
        currently only valid for 8-bit 'crc'. Used to confirm the
        device hasn't just implemented a simple checksum instead of
        a real crc.
        """
        
        if self.crclen == 1:
            logging.info("Checking for linear code")
        else:
            logging.info("16-bit or 32-bit CRC, skipping linear code check")
            return False
        
        diffout = []
        
        # Linear code that is a real checksum
        
        for i, m in enumerate(messages):
            test = 0
            for d in m:
                test += d
            test &= 0xff
            diffout.append(test ^ crcs[i][0])

        if len(set(diffout)) == 1:
            print("\nPossible linear code and not CRC: sum(m) XOR 0x%02X"%diffout[0])
            print("This solution works on all %d inputs!"%len(messages))
            
            if print_examples:
                print("********** example usage *************")
                print("def my_checksum(message):")
                print("  checksum = 0")
                print("  for d in message:")
                print("    checksum += d")
                print("  checksum = (checksum & 0xff) ^ 0x%02x"%diffout[0])
                print("  return checksum")
                print("**************************************")
            return True

        diffout = []
        
        # Linear code that XORs each byte
        
        for i, m in enumerate(messages):
            test = 0
            for d in m:
                test ^= d
            test &= 0xff
            diffout.append(test ^ crcs[i][0])
        
        if len(set(diffout)) == 1:
            print("\nPossible linear code and not CRC: xorsum(m) XOR 0x%02X"%diffout[0])
            print("This solution works on all %d inputs!"%len(messages))
            
            if print_examples:
                print("********** example usage *************")
                print("def my_checksum(message):")
                print("  checksum = 0")
                print("  for d in message:")
                print("    checksum ^= d")
                print("  checksum = (checksum & 0xff) ^ 0x%02x"%diffout[0])
                print("  return checksum")
                print("**************************************")
            return True
        
        return False
    
    def search(self, messages, crcs, print_examples=True):
        """
        Uses input `messages`-`crcs` pairs to find potential crc parameters.
        
        Normally the crc would just be the ending bytes of the message. The crc size
        is detected based on number of bytes for each crc. The crc endianness will be
        auto detected, so pass the crc in the same manner as used in your communication
        protocol.
        """

        self.validate_inputs(messages, crcs)
        message_size_dict = self.message_size_dict

        if len(message_size_dict.keys()) == 1:
            print("NOTE: Output parameters may be specific to this message size only. Pass different length messages if possible.")
        
        self.search_linear(messages, crcs, print_examples)
        
        candidates = []
        
        ## Searching
        for message_len in message_size_dict.keys():

            print("\nWorking on messages of %d length: "%(message_len))

            if message_size_dict[message_len]["num"] > 1:
                #Need at least two messages of this length to do difference...
                diffsets = []
                for i, idx in enumerate(message_size_dict[message_len]["indexes"]):
                    try:
                        msg1idx = message_size_dict[message_len]["indexes"][i+0]
                        msg2idx = message_size_dict[message_len]["indexes"][i+1]
                        logging.info("Using diff between message %d & %d"%(msg1idx, msg2idx))
                        diff = [messages[msg1idx][i] ^ messages[msg2idx][i] for i in range(0, len(messages[msg1idx]))]
                        diffcrc = [crcs[msg1idx][i] ^ crcs[msg2idx][i] for i in range(0, len(crcs[msg1idx]))]                        
                        
                        for d in ALLCRCCLASSES:
                            if d._width == self.crclen * 8:
                                
                                logging.debug("Trying class: %r"%d)
                                
                                res = d.calc(messages[msg1idx])
                                
                                # We'll figure out actual XOR output later
                                d._xor_output  = 0
                                d._initvalue  = 0 # This will get packed into _xor_output
                                                  # at some point should be smarter about it, and set
                                                  # init value to 'real' one to see if that is case.
                                
                                res = d.calc(diff)
                                
                                #Deal with unknown CRC order, kinda hacky but YOLO
                                if self.crclen == 1:
                                    if diffcrc[0] == res:
                                        candidates.append({"class":d, "order":"le"})
                                    packstr = "B"
                                        
                                if self.crclen == 2 or self.crclen == 4:
                                    if self.crclen == 2:
                                        packstr = "H"
                                    else:
                                        packstr = "I"
                                        
                                    testcrc = list(struct.pack("<"+packstr, res)) #LE
                                    if list(diffcrc) == testcrc:
                                        candidates.append({"class":d, "order":"le"})
                                    testcrc = list(struct.pack(">"+packstr, res)) #BE
                                    if list(diffcrc) == testcrc:
                                        candidates.append({"class":d, "order":"be"})
                        
                        cset = set()
                        for c in candidates:
                            #Convert to string to make validating in set easier, will convert back later
                            newc = "poly:"+hex(c["class"]._poly)+" reflectin:"+str(c["class"]._reflect_input) +\
                                   " reflectout:"+str(c["class"]._reflect_output)+" init:"+hex(c["class"]._initvalue) +\
                                   " order:"+c["order"] + " crclen:"+str(self.crclen)
                            cset.add(newc)
                        
                        if len(cset) == 0:
                            logging.warning("No parameters for difference messages %d to %d"%(msg1idx, msg2idx))
                        else:
                            logging.info("Parameters for difference messages: %s"%str(cset))
                        diffsets.append(cset)
                    except IndexError as e:
                        #TODO - overextends itself and uses execption to figure out end, shoudl be smarter
                        logging.debug("Exception - hopefully correct one: %r"%e)
                        break
                logging.info("For %d diffs of length %d, found sets: %s"%(len(message_size_dict[message_len]["indexes"])-1, message_len, str(diffsets)))
                
                if len(diffsets) == 0:
                    print("  Failed to find solution.")
                else:                
                    intersect = set.intersection(*diffsets)
                
                    if len(intersect) == 0:
                        if len(diffsets) > 0:
                            print("  Failed to find common solution. Possible solutions: %s"%(str(diffsets)))
                        else:
                            print("  Failed to find any solutions. Possibly not a real CRC, implementation error, or non-standard polynomial")
                    elif len(intersect) == 1:
                        print("  Found single likely solution for differences of len=%d, yah!"%(message_len))
                    else:
                        print("  Found multiple solutions for differences of len=%d"%(message_len))
                    
                    for sol in intersect:
                        #Calc crc
                        test = [a.split(":") for a in sol.split(" ")]
                        crcdict = { a[0]:a[1] for a in test }
                        #Convert from str back to dict
                        crcdict['crclen'] = int(crcdict['crclen'])
                        crcdict['poly'] = int(crcdict['poly'], 16)
                        crcdict['init'] = int(crcdict['init'], 16)
                        crcdict['reflectin'] = crcdict['reflectin'] == "True"
                        crcdict['reflectout'] = crcdict['reflectout'] == "True"
                        
                        if self.crclen == 1:
                            crc = Crc8Base
                        elif self.crclen == 2:
                            crc = Crc16Base
                        elif self.crclen == 4:
                            crc = Crc32Base
                        
                        packstr = self.crcdict_to_packstr(crcdict)
                        
                        crc._poly = crcdict['poly']
                        crc._reflect_input = crcdict['reflectin']
                        crc._reflect_output = crcdict['reflectout']
                        crc._initvalue = crcdict['init']
                        crc._xor_output = 0
                        
                        crcouts = []
                        
                        for idx in message_size_dict[message_len]["indexes"]:
                            testcrc = crc.calc(messages[idx])
                            realcrc = struct.unpack(packstr, bytes(crcs[idx]))[0]
                            crcouts.append(testcrc ^ realcrc)
                        
                        xorout = set(crcouts)
                        
                        if len(xorout) == 1:
                            print("  Found single XOR-out value for len = %d: 0x%X"%(message_len, crcouts[0]))
                            crcdict['xor_output'] = list(xorout)[0]
                            
                            if print_examples:
                                print("********** example usage *************")
                                self.print_crc_example(crcdict, messages[message_size_dict[message_len]["indexes"][0]])
                                print("**************************************")
                            
                            print("If you have multiple message lengths this solution may be valid for this only.")

                        else:
                            print("Multiple XOR-out solutions, **SOLVE FAILED**. Debugging info only:")
                            print(xorout)
                            crcdict['xor_output'] = None
            else:
                print("  Single message of this sized - skipped for now")
                    