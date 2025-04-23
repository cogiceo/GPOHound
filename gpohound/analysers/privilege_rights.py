from gpohound.utils.utils import load_yaml_config


class PrivilegeRightsAnalyser:
    """Analyse Privilege Rights"""

    def __init__(self, ad_utils, config="config.analysis", config_file="privilege_rights.yaml"):
        self.ad_utils = ad_utils
        self.privileged_groups = load_yaml_config(config, config_file)

    def analyse(self, processed_gpo):
        """
        Get trustees that can elevate their privilege using User Rights Assignment
        """

        output = {}

        privilege_rights = processed_gpo.get("Machine", {}).get("Privilege Rights")
        if privilege_rights:
            for privilege, trustees in privilege_rights.items():
                not_default = []
                if privilege in self.privileged_groups.keys():
                    dangereous_privilege = self.privileged_groups.get(privilege)

                    # Iterates over trustees that have dangerous privilege
                    for trustee in trustees:
                        sid = trustee.get("sid")

                        # Don't take into account default trustees and service account SID
                        if sid and (
                            sid in dangereous_privilege.get("default_trutees", []) or sid.startswith("S-1-5-8")
                        ):
                            continue

                        not_default.append(trustee)

                    if not_default:
                        entry = {
                            "analysis": dangereous_privilege.get("analysis"),
                            "edge": dangereous_privilege.get("edge"),
                            "references": dangereous_privilege.get("references"),
                            "trustees": not_default,
                        }

                        output[privilege] = entry
        if output:
            return {"Machine": output}

        return output
