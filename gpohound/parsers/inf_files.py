import re
from gpohound.utils.utils import load_yaml_config


class INFParser:
    """Parse .inf files"""

    def __init__(self, config="config.gpo_files_structure.inf") -> None:

        # Load INF files
        self.config = load_yaml_config(config)

        # Regular expressions to identify sections and key/value pairs
        self.section_pattern = re.compile(r"\[\s*(.*?)\s*\]")

        # Registry Values types
        self.reg_types = {
            "0": "REG_NONE",
            "1": "REG_SZ",
            "2": "REG_EXPAND_SZ",
            "3": "REG_BINARY",
            "4": "REG_DWORD",
            "5": "REG_DWORD_BIG_ENDIAN",
            "6": "REG_LINK",
            "7": "REG_MULTI_SZ",
            "8": "REG_RESOURCE_LIST",
            "9": "REG_FULL_RESOURCE_DESCRIPTOR",
            "10": "REG_RESOURCE_REQUIREMENTS_LIST",
            "11": "REG_QWORD",
        }

    def parse(self, file_path, file_name):
        """
        Read an INF file and populate the results dictionary with its contents
        """

        file_config = self.config.get(file_name.lower())

        if not file_config:
            return None

        current_section = None

        with open(file_path, "r", encoding="utf-16") as f:
            results = {}

            for line in f:
                line = line.strip()
                # Ignore empty lines or comments
                if not line or line.startswith(";"):
                    continue

                # Check if the line is a section
                section_match = self.section_pattern.match(line)
                if section_match:
                    # Extract the section name
                    current_section = section_match.group(1)
                    if current_section not in results:
                        if "include" in file_config.get(current_section, {}):
                            results[current_section] = {}
                        continue

                # Parse strings list
                if (
                    file_config.get(current_section).get("type") == "string-list"
                    and "include" in file_config[current_section]
                ):
                    if results.get(current_section):
                        idx = len(results.get(current_section)) + 1
                    else:
                        idx = 1
                    entry = {str(idx): line.strip('"')}
                    results[current_section].update(entry)

                # Parse Key = Value settings
                if file_config.get(current_section).get("type") == "key-value":
                    key_value_match = line.split("=", 1)

                    if len(key_value_match) == 2:
                        key, value = key_value_match
                        key = key.strip().strip('"')
                        value = value.strip()

                        if "include" in file_config[current_section]:

                            # Privilege Rights
                            if (
                                current_section == "Privilege Rights"
                                and key in file_config[current_section]["attributes"]
                            ):
                                results[current_section][key] = value.split(",")

                            # Group Membership
                            elif current_section == "Group Membership":
                                values = value.split(",")

                                if not value:
                                    continue

                                if "__Members" in key:
                                    group_name = key.replace("__Members", "")
                                    membership = "Members"
                                elif "__Memberof" in key:
                                    group_name = key.replace("__Memberof", "")
                                    membership = "Memberof"
                                else:
                                    continue

                                if membership not in file_config[current_section]["attributes"]:
                                    continue

                                results.setdefault(current_section, {}).setdefault(group_name, {}).update(
                                    {membership: values}
                                )

                            # Registry Values
                            elif current_section == "Registry Values":
                                value_type, registry_value = value.split(",", 1)
                                if key.startswith("USER"):
                                    hive = "HKEY_USERS"
                                else:
                                    hive = "HKEY_LOCAL_MACHINE"
                                entry = {
                                    "Hive": hive,
                                    "Type": self.reg_types[value_type],
                                    "Data": registry_value.strip('"'),
                                }

                                entry = {
                                    key: {attr: entry[attr] for attr in file_config[current_section]["attributes"]}
                                }
                                results[current_section].update(entry)

                            # Simple Key Value
                            elif key in file_config[current_section]["attributes"]:
                                results[current_section][key] = value.strip('"')

                # Parse comma-separated settings
                if file_config.get(current_section).get("type") == "comma-separated":
                    key, value = line.split(",", 1)
                    key = key.strip('"')
                    attr1, attr2 = [items.strip('"') for items in value.split(",", 1)]

                    # Registry Keys and File Security
                    if current_section == "Registry Keys" or current_section == "File Security":
                        entry = {"PermPropagationMode": attr1, "AclString": attr2}
                        entry = {key: {attr: entry[attr] for attr in file_config[current_section]["attributes"]}}
                        results[current_section].update(entry)

                    # Service General Setting
                    elif current_section == "Service General Setting":
                        entry = {"AclString": attr1, "StartupMode": attr2}
                        entry = {key: {attr: entry[attr] for attr in file_config[current_section]["attributes"]}}
                        results[current_section].update(entry)

        if results:
            return {file_name + ".inf": results}
        return None
