class PrivilegeRightsProcessor:
    """Process Privilege Rights"""

    def __init__(self, ad_utils):
        self.ad_utils = ad_utils

    def process(self, settings):
        """
        Extract the "Privilege Rights" settings that will be applied to a computer
        Resolves SID of trustees contained in privilege rights
        """

        output = {}

        for privilege, trustees in settings.items():

            for trustee in trustees:

                if trustee:
                    found_trustee = self.ad_utils.get_trustee(trustee)
                    output.setdefault(privilege, []).append(
                        {
                            "name": found_trustee.get("name"),
                            "sid": found_trustee.get("sid"),
                        }
                    )

        return output
