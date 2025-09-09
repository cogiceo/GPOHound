import struct
from gpohound.utils.utils import load_yaml_config


class POLParser:
    """Parse Registry.pol files"""

    def __init__(self, config="config.gpo_files_structure.pol"):
        self.config = load_yaml_config(config)
        self.magic_string = b"\x50\x52\x65\x67\x01\x00\x00\x00"
        self.reg_types = {
            0: "REG_NONE",
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            5: "REG_DWORD_BIG_ENDIAN",
            6: "REG_LINK",
            7: "REG_MULTI_SZ",
            8: "REG_RESOURCE_LIST",
            9: "REG_FULL_RESOURCE_DESCRIPTOR",
            10: "REG_RESOURCE_REQUIREMENTS_LIST",
            11: "REG_QWORD",
        }

    def reg_value_to_string(self, keytype, keyvalue):
        """
        Convert registry values to string if possible
        """

        # Remove the "0x" prefix if present
        if keyvalue.upper().startswith("0X"):
            hex_str = keyvalue[2:]
        else:
            hex_str = keyvalue

        try:
            if keytype in ["REG_DWORD", "REG_QWORD"]:
                num_val = int(hex_str, 16)
                return str(num_val)
            elif keytype in ["REG_SZ", "REG_EXPAND_SZ"]:
                b = bytes.fromhex(hex_str)
                return b.decode("utf-8", errors="replace").replace("\x00", "")[::-1]
            elif keytype == "REG_MULTI_SZ":
                b = bytes.fromhex(hex_str)
                return b.decode("utf-8", errors="replace").replace("\x00\x00\x00", ",").replace("\x00", "")[::-1]
            elif keytype == "REG_NONE":
                return None
            else:
                return keyvalue

        # If we can not convert just return the hex value
        except ValueError:
            return keyvalue

    def parse(self, pol_file, policy_type):
        """Parse contents of Registry.pol file to a dictionary"""

        results = {}

        with open(pol_file, "rb") as f:
            file_data = f.read()

        body = file_data[len(self.magic_string) :]

        while len(body) > 0:
            if body[0:2] != b"[\x00":
                break
            body = body[2:]

            # Key
            key, _, body = body.partition(b";\x00")
            key = key.decode("utf-16-le").strip("\x00")

            # Value
            value, _, body = body.partition(b";\x00")
            value = value.decode("utf-16-le").strip("\x00")

            # Type
            reg_type = body[0:4]
            body = body[4 + 2 :]  # len of field plus semicolon delimieter
            reg_type = struct.unpack("<I", reg_type)[0]
            reg_type = self.reg_types[reg_type]

            # Size
            size = body[0:4]
            body = body[4 + 2 :]
            size = struct.unpack("<I", size)[0]

            # Data
            data = f"0x{int.from_bytes(body[0:size], 'little'):08X}"
            body = body[size:]

            if "include" in self.config[reg_type]:
                data = self.reg_value_to_string(reg_type, data)

                # Not sure if this works everytime
                if policy_type.upper() == "USER":
                    hive = "HKEY_CURRENT_USER"
                else:
                    hive = "HKEY_LOCAL_MACHINE"

                reg_dict = {
                    "Hive": hive,
                    "Type": reg_type,
                    "Size": str(size),
                    "Data": data,
                }
                result = {f"{key}\\{value}": {attr: reg_dict[attr] for attr in self.config[reg_type]["attributes"]}}
                results.update(result)

            if body[0:2] != b"]\x00":
                break
            body = body[2:]

        if results:
            return {"registry.pol": results}
        return None
