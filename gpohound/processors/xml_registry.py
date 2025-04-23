from gpohound.utils.utils import find_keys_recursive


class XMLRegistryProcessor:
    """Process XML"""

    def __init__(self, ad_utils=None):
        self.ad_utils = ad_utils

    def process(self, settings):
        """
        Extract registry.xml settings to fit the format for registy key analysis
        """
        action_type = {"D": "DELETE", "U": "UPDATE", "C": "CREATE", "R": "REPLACE"}

        output = []

        # Find Registry settings as it can be embeded in collections
        found_registries = find_keys_recursive(settings, "Registry").get("Registry")

        if found_registries:

            for found_registry in found_registries:

                registries = found_registry.get("value")

                if isinstance(registries, dict):
                    registries = [registries]

                for registry in registries:

                    # Extract properties and output registry key in the correct format
                    properties = registry.get("Properties")
                    action = action_type.get(properties.get("action"), "UPDATE")

                    if properties.get("type") == "REG_DWORD":
                        data = str(int(properties.get("value"), 16))
                    else:
                        data = properties.get("value")

                    entry = {
                        "Hive": properties.get("hive"),
                        "Key": properties.get("key") + "\\" + properties.get("name"),
                        "Type": properties.get("type"),
                        "Data": data,
                        "Action": action,
                    }

                    output.append(entry)

        return output
