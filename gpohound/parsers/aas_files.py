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

    def __init__(self, config="config.gpo_files_structure.aas") -> None:
        self.config = load_yaml_config(config)

    def parse_args(self, data, file_name):
        """
        Parse data as specified in section the 2.2.4 section of the MS-GPSI :
        - https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-GPSI/%5bMS-GPSI%5d.pdf
        """
        dtype = struct.unpack("<H", data.read(2))[0]

        if dtype == AASParser.DATA_TYPE_NULL or dtype == AASParser.DATA_TYPE_NULL_ARG:
            return None
        elif dtype == AASParser.DATA_TYPE_INT32:
            return struct.unpack("<i", data.read(4))[0]
        elif dtype == AASParser.DATA_TYPE_INT32:
            return struct.unpack("<i", data.read(4))[0]
        elif dtype == AASParser.DATA_TYPE_EXTENDED:
            ext_len = struct.unpack("<I", data.read(4))[0]
            real_type = (ext_len >> 30) & 0x3
            length = ext_len & 0x3FFFFFFF
            if real_type == 0:
                raw = data.read(length)
                try:
                    return raw.decode()
                except UnicodeDecodeError as e:
                    logging.debug("Decoding error for aas file %s: %s", file_name, e)
                    return raw
            elif real_type == 1 or real_type == 2:
                return data.read(length)
        else:
            length = dtype & 0x3FFF
            dtype = dtype & 0xC000
            if dtype == AASParser.DATA_TYPE_NULL:
                raw = data.read(length)
                try:
                    return raw.decode()
                except UnicodeDecodeError as e:
                    logging.debug("Decoding error for aas file %s: %s", file_name, e)
                    return raw
            else:
                return data.read(length)

    def parse(self, file_path, file_name):
        """
        Parse Application Advertise Script
        """

        if "include" in self.config["aas"]:
            records = {}

            with open(file_path, "rb") as f:
                data = BytesIO(f.read())

            while True:
                opcode, arg_count = struct.unpack("<BB", data.read(2))
                args = [self.parse_args(data, file_name) for _ in range(arg_count)]
                records.setdefault(opcode, []).append(args)
                if opcode == 3:  # End opcode
                    break

            if 4 in records and 9 in records:
                product_info = records.get(4)[0]
                source_list_publish = records.get(9)[0]
                raw_output = {
                    "Product Key": product_info[0],
                    "Product Name": product_info[1],
                    "Launch Path": source_list_publish[8],
                    "Package Name": product_info[2],
                }
                output = {key: raw_output[key] for key in self.config["aas"]["attributes"] if key in raw_output}
                return {file_name: output}

        return None
