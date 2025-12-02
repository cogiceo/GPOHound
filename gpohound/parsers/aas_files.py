import struct
import logging
from io import BytesIO
from gpohound.utils.utils import load_yaml_config


class AASParser:
    """Parse .aas files"""

    DATA_TYPE_NULL = 0x0000
    DATA_TYPE_INT32 = 0x4000
    DATA_TYPE_NULL_ARG = 0x8000
    DATA_TYPE_EXTENDED = 0xC000
    DATA_TYPE_ASCIICHAR = 0x0000
    DATA_TYPE_BINARYSTRM = 0x8000
    DATA_TYPE_UNICODESTR = 0xC000

    def __init__(self, config="config.gpo_files_structure.aas") -> None:
        self.config = load_yaml_config(config)
        self.file_name = None
        self.data = None

    def parse_args(self):
        """
        Parse data as specified in section 2.2.4 of the MS-GPSI :
        - https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-GPSI/%5bMS-GPSI%5d.pdf
        """

        type_length = struct.unpack("<H", self.data.read(2))[0]
        dtype = type_length & 0xC000
        length = type_length & 0x3FFF

        if length == 0:
            # Null string or Null argument
            if dtype == AASParser.DATA_TYPE_NULL or dtype == AASParser.DATA_TYPE_NULL_ARG:
                return None

            # 32-bit signed integer
            elif dtype == AASParser.DATA_TYPE_INT32:
                return struct.unpack("<i", self.data.read(4))[0]

            # Extended size
            elif dtype == AASParser.DATA_TYPE_EXTENDED:
                ext_type_length = struct.unpack("<I", self.data.read(4))[0]
                ext_length = ext_type_length & 0x3FFFFFFF
                ext_dtype = (ext_type_length & 0xC0000000) >> 16
                return self.read_steam_data(ext_dtype, ext_length)
        else:
            # Parse stream values
            return self.read_steam_data(dtype, length)

    def read_steam_data(self, dtype, length):
        """
        Read stream values such as ASCII char string, binary stream, or Unicode string
        """

        # ASCII char string
        if dtype == AASParser.DATA_TYPE_ASCIICHAR:
            raw = self.data.read(length)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as e:
                logging.debug("Decoding error for aas file %s: %s", self.file_name, e)
                return raw.hex()

        # Binary stream
        elif dtype == AASParser.DATA_TYPE_BINARYSTRM:
            return self.data.read(length).hex()

        # Unicode string
        elif dtype == AASParser.DATA_TYPE_UNICODESTR:
            raw = self.data.read(length * 2)
            try:
                return raw.decode("utf-16le")
            except UnicodeDecodeError as e:
                logging.debug("Unicode Decoding error for aas file %s: %s", self.file_name, e)
            return raw.hex()

    def parse(self, file_path, file_name):
        """
        Parse Application Advertise Script
        """

        if "include" in self.config["aas"]:
            records = {}

            self.file_name = file_name

            with open(file_path, "rb") as f:
                self.data = BytesIO(f.read())

            while True:
                opcode, arg_count = struct.unpack("<BB", self.data.read(2))
                args = [self.parse_args() for _ in range(arg_count)]
                records.setdefault(opcode, []).append(args)

                # print(opcode, args) # Print all infos contained in the AAS file
                # End opcode
                if opcode == 3:
                    break

            if 4 in records and 9 in records:
                product_info = records.get(4)[0]
                source_list_publish = records.get(9)[0]
                raw_output = {
                    "Product Key": product_info[0],
                    "Product Name": product_info[1],
                    "Launch Path": source_list_publish[-1],
                    "Package Name": product_info[2],
                }
                output = {key: raw_output[key] for key in self.config["aas"]["attributes"] if key in raw_output}
                return {file_name: output}

        return None
