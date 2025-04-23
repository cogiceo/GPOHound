class POLRegistryProcessor:
    """Process registry.pol"""

    def __init__(self, ad_utils=None):
        self.ad_utils = ad_utils

    def process(self, settings):
        """
        Format registy key for analysis
        """

        output = []

        for reg_key, data in settings.items():

            # Set as DELETE options if key contains "**del"
            # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format
            if "**del" in reg_key.lower():
                action = "DELETE"
            else:
                action = "UPDATE"

            entry = {
                "Hive": data.get("Hive"),
                "Key": reg_key,
                "Type": data.get("Type"),
                "Data": data.get("Data"),
                "Action": action,
            }
            output.append(entry)
        return output
