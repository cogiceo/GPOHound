class RegistryValuesProcessor:
    """Process Registry Values"""

    def __init__(self, ad_utils=None):
        self.ad_utils = ad_utils

    def process(self, settings):
        """
        Format registy key for analysis
        """
        output = []
        for reg_key, data in settings.items():
            entry = {
                "Hive": data.get("Hive"),
                "Key": reg_key.split("\\", 1)[1],
                "Type": data.get("Type"),
                "Data": data.get("Data"),
                "Action": "UPDATE",
            }
            output.append(entry)
        return output
