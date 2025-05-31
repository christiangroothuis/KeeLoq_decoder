##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2024 Andrea Orazi <andrea.orazi@gmail.com>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##


import sigrokdecode as srd


class Ann:
    TE, LOGICAL_BIT, CODE_WORD, ENCRYP_DATA, FIXED_DATA = range(5)


class Decoder(srd.Decoder):
    api_version = 3
    id = "keyloq"
    name = "KeyLoq"
    longname = "KeeLoq CodeWord Decoder"
    desc = "Keeloq CodeWord Decoder for Pulseview"
    license = "gplv2+"
    inputs = ["logic"]
    outputs = []
    tags = ["Security/crypto"]
    channels = ({"id": "pwm", "name": "PWM", "desc": "Code Word Channel"},)
    options = ()

    annotations = (
        ("te", "TE"),
        ("logical_bit", "Logical Bit"),
        ("Code_Word", "Code Word"),
        ("encryp_data", "Encrypted Data"),
        ("fixed_data", "Fixed Data"),
    )
    annotation_rows = (
        ("bits", "Bits", (Ann.TE, Ann.LOGICAL_BIT)),
        ("code word", "Code Word", (Ann.CODE_WORD,)),
        ("data", "Data", (Ann.ENCRYP_DATA, Ann.FIXED_DATA)),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.samplerate = None
        self.TEcnt = 0  # TE counter
        self.Block_Init = 0  # Flag for each block of info
        # TE Timing - According to documentation a TE is typically 400 usecs
        # [0][1] - TE/Logical Bit 1 | [2][3] - Logical Bit 0 | [4][5] - Header Length
        self.TE_Timing = [280e-6, 580e-6, 700e-6, 1000e-6, 3e-3, 6e-3]
        # Preamble thresholds:
        #   Standard preamble: 23 TEs @ ~400µs
        #   Short preamble:   45 TEs @ ~200µs
        self.PREAMBLE_TE_Count_Std = 23
        self.PREAMBLE_TE_Count_Short = 45
        # Short‐TE timing window (half of standard TE range: 140–290 µs)
        self.PREAMBLE_TE_Timing_Short = [
            self.TE_Timing[0] * 0.5,  # 140e-6
            self.TE_Timing[1] * 0.5,  # 290e-6
        ]
        self.ssBlock = 0  # Sample number of a block of information
        self.Header_Completed = 0  # [ 0 = Not Complete 1 = Complete]
        self.n = 0  # Current Sample number
        self.prevN = 0  # Previous sample number
        self.Bitcnt = 0  # Bit counter in Data Portion
        self.trig_cond = ""  # Wait - trigger condition
        self.BitString = ""  # A string of Logical Bit Code Word
        self.KeyLoq = {
            "Encrypted": "",
            "Serial-Number": "",
            "S3": "",
            "S0": "",
            "S1": "",
            "S2": "",
            "V-Low": "",
            "RPT": "",
        }  # KeyLoq Code Word

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    # Define the beginning of each useful block of information saving the Sample Number
    def Start_Block(self):
        if self.Block_Init == 0:
            self.Block_Init = 1
            self.ssBlock = self.prevN

    # Shows Preamble + Header (supports both short and standard TE preambles)
    def Decode_Preable(self, t):
        # Check for short‐TE range (≈ 200 µs) or standard TE range (≈ 400 µs)
        in_short_te = (t >= self.PREAMBLE_TE_Timing_Short[0] and t <= self.PREAMBLE_TE_Timing_Short[1])
        in_std_te = (t >= self.TE_Timing[0] and t <= self.TE_Timing[1])

        # Preamble detection
        if in_short_te or in_std_te:
            # Short preamble counting
            if in_short_te and (self.TEcnt < self.PREAMBLE_TE_Count_Short):
                self.put(
                    self.prevN,
                    self.samplenum,
                    self.out_ann,
                    [Ann.TE, [str(self.TEcnt)]],
                )
                self.Start_Block()
            # Standard preamble counting
            elif in_std_te and (self.TEcnt < self.PREAMBLE_TE_Count_Std):
                self.put(
                    self.prevN,
                    self.samplenum,
                    self.out_ann,
                    [Ann.TE, [str(self.TEcnt)]],
                )
                self.Start_Block()

            # When TEcnt reaches one of the thresholds, mark Preamble
            if (in_short_te and self.TEcnt == self.PREAMBLE_TE_Count_Short) or (
                in_std_te and self.TEcnt == self.PREAMBLE_TE_Count_Std
            ):
                self.put(
                    self.ssBlock,
                    self.n,
                    self.out_ann,
                    [Ann.CODE_WORD, ["Preamble"]],
                )
                self.put(
                    self.prevN,
                    self.samplenum,
                    self.out_ann,
                    [0, [str(self.TEcnt)]],
                )

        # Header detection: next TE after preamble should be ~10× TE (3–6 ms)
        elif (
            (t >= self.TE_Timing[4] and t <= self.TE_Timing[5])
            and (self.TEcnt == self.PREAMBLE_TE_Count_Std + 1
                 or self.TEcnt == self.PREAMBLE_TE_Count_Short + 1)
        ):
            self.put(self.prevN, self.n, self.out_ann, [Ann.CODE_WORD, ["Header"]])
            self.TEcnt = 0
            self.Block_Init = 0
            self.Header_Completed = 1  # Is 1 when decoder has finished Preamble + Header

        else:  # Reset Counters because this is not a TE
            self.TEcnt = 0
            self.Block_Init = 0

    # In Data Portion bits are encoded using PWM technique
    def Decode_LogicalBit(self, t):
        # Logic Bit 0 = 2 TE at High Level + 1 TE at low level >> typically 800 usec (H) + 400 usec (L) <<
        # Logic Bit 1 = 1 TE at High Level + 2 TE at Low Level >> typically 400 usec (H) + 800 usec (L) <<
        # Thus, to recognise a logical bit we have to read two subsequent edges (or half‐bits)

        LogicalBit = ""  # Either '0' or '1' encoded using PWM
        Valid_Bit = 0

        # Check timing validity first (half‐bit: ~400 µs or ~800 µs)
        if (t >= self.TE_Timing[0] and t <= self.TE_Timing[1]) or (
            t >= self.TE_Timing[2] and t <= self.TE_Timing[3]
        ):
            Valid_Bit = 1

            if Valid_Bit:
                self.Start_Block()

                # Gets the the next second half of the logical bit to fully decode it
                if self.Bitcnt == 65:  # Last bit needs special care as definitely there is no next edge
                    self.n = self.samplenum + 8  # Arbitrary sample# after last to complete this bit
                else:
                    self.wait(self.trig_cond)
                    self.n = self.samplenum

                # After time validity, check whether it is '1' or '0'
                if t >= self.TE_Timing[0] and t <= self.TE_Timing[1]:
                    LogicalBit = "1"
                else:
                    LogicalBit = "0"

                self.put(
                    self.prevN,
                    self.n,
                    self.out_ann,
                    [Ann.LOGICAL_BIT, ["Bit " + LogicalBit]],
                )
                return LogicalBit

        else:  # Invalid bit timing → reset counters
            self.put(
                self.prevN,
                self.n,
                self.out_ann,
                [Ann.LOGICAL_BIT, [">>> Invalid Bit <<< " + LogicalBit]],
            )
            self.Reset_DP_Cnts()
            self.Header_Completed = 0
            self.Bitcnt = -1  # Will be set to 0 in main decode loop
            return "0"

    # Reset Data Portion counters at the end of each decoded block
    def Reset_DP_Cnts(self):
        self.Block_Init = 0
        self.BitString = ""

    # Convert a Binary string into the equivalent value in Hex (0x...) as a string
    def Bin2Hex(self):
        decimal_value = int(self.BitString, 2)
        # Convert integer to hexadecimal with leading zeroes (7 hex digits)
        hex_value = "0x{0:0{1}X}".format(decimal_value, 7)
        return hex_value

    # Decode all logical PWM bits from 0 to 65, completing the CodeWord
    def Decode_DataPortion(self, t):
        # Bits 0-31: Encrypted portion (comes from the KeeLoq algorithm)
        if self.Bitcnt <= 31:
            # LSB is transmitted first; prepend to BitString so MSB ends last
            self.BitString = self.Decode_LogicalBit(t) + self.BitString

            if self.Bitcnt == 31:
                self.put(
                    self.ssBlock,
                    self.n,
                    self.out_ann,
                    [Ann.CODE_WORD, ["Encrypted Portion"]],
                )
                self.KeyLoq["Encrypted"] = self.Bin2Hex()
                self.put(
                    self.ssBlock,
                    self.n,
                    self.out_ann,
                    [Ann.ENCRYP_DATA, [self.KeyLoq["Encrypted"]]],
                )
                self.Reset_DP_Cnts()

        # Bits 32-59: Serial Number (Fixed portion)
        elif self.Bitcnt >= 32 and self.Bitcnt <= 59:
            self.BitString = self.Decode_LogicalBit(t) + self.BitString

            if self.Bitcnt == 59:
                self.put(
                    self.ssBlock,
                    self.n,
                    self.out_ann,
                    [Ann.CODE_WORD, ["Serial Number"]],
                )
                self.KeyLoq["Serial-Number"] = self.Bin2Hex()
                self.put(
                    self.ssBlock,
                    self.n,
                    self.out_ann,
                    [Ann.FIXED_DATA, [self.KeyLoq["Serial-Number"]]],
                )
                self.Reset_DP_Cnts()

        # Bits 60-63: Button Code (S3, S0, S1, S2)
        elif self.Bitcnt >= 60 and self.Bitcnt <= 63:
            LogicalBit = self.Decode_LogicalBit(t)

            if self.Bitcnt == 60:
                self.KeyLoq["S3"] = LogicalBit
                self.put(
                    self.prevN,
                    self.n,
                    self.out_ann,
                    [Ann.FIXED_DATA, ["S3 = " + self.KeyLoq["S3"]]],
                )
            elif self.Bitcnt == 61:
                self.KeyLoq["S0"] = LogicalBit
                self.put(
                    self.prevN,
                    self.n,
                    self.out_ann,
                    [Ann.FIXED_DATA, ["S0 = " + self.KeyLoq["S0"]]],
                )
            elif self.Bitcnt == 62:
                self.KeyLoq["S1"] = LogicalBit
                self.put(
                    self.prevN,
                    self.n,
                    self.out_ann,
                    [Ann.FIXED_DATA, ["S1 = " + self.KeyLoq["S1"]]],
                )
            elif self.Bitcnt == 63:
                self.KeyLoq["S2"] = LogicalBit
                self.put(
                    self.ssBlock, self.n, self.out_ann, [Ann.CODE_WORD, ["Button Code"]]
                )
                self.put(
                    self.prevN,
                    self.n,
                    self.out_ann,
                    [Ann.FIXED_DATA, ["S2 = " + self.KeyLoq["S2"]]],
                )
                self.Reset_DP_Cnts()

        # Bit 64: V-Low status
        elif self.Bitcnt == 64:
            LogicalBit = self.Decode_LogicalBit(t)

            self.put(self.ssBlock, self.n, self.out_ann, [Ann.CODE_WORD, ["V-Low"]])
            if LogicalBit == "0":
                self.KeyLoq["V-Low"] = "Battery High"
            else:
                self.KeyLoq["V-Low"] = "Battery Low"

            self.put(
                self.prevN,
                self.n,
                self.out_ann,
                [Ann.FIXED_DATA, [self.KeyLoq["V-Low"]]],
            )
            self.Reset_DP_Cnts()

        # Bit 65: Repeat (RPT)
        elif self.Bitcnt == 65:
            LogicalBit = self.Decode_LogicalBit(t)

            self.put(self.ssBlock, self.n, self.out_ann, [Ann.CODE_WORD, ["RPT"]])
            if LogicalBit == "0":
                self.KeyLoq["RPT"] = "No"
            else:
                self.KeyLoq["RPT"] = "Yes"

            self.put(
                self.prevN, self.n, self.out_ann, [Ann.FIXED_DATA, [self.KeyLoq["RPT"]]]
            )
            self.Reset_DP_Cnts()
            self.Header_Completed = 0  # Looks for another new CodeWord
            self.Bitcnt = -1  # To start from 0 in main decode()

    # Main Loop
    def decode(self):
        if self.samplerate is None:
            raise Exception("Cannot decode without samplerate.")

        t = 0  # Time between two edges

        # Each CodeWord begins with a Rising Edge.
        self.trig_cond = [{0: "r"}]  # Go and look for it
        self.wait(self.trig_cond)
        self.prevN = self.samplenum

        self.trig_cond = [{0: "e"}]  # Go to the next Edge

        while True:

            self.wait(self.trig_cond)
            self.n = self.samplenum

            # Get time (usec) between the current and the previous sample
            t = (self.n - self.prevN) / self.samplerate

            # CodeWord decoding subfunctions
            if self.Header_Completed == 0:
                self.TEcnt += 1
                self.Decode_Preable(t)
            else:
                self.Decode_DataPortion(t)
                self.Bitcnt += 1

            # Ready for the next cycle
            self.prevN = self.samplenum
