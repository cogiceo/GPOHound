from gpohound.processors.group_membership import GroupMembershipProcessor
from gpohound.processors.xml_groups import XMLGroupsProcessor

from gpohound.processors.registry_values import RegistryValuesProcessor
from gpohound.processors.xml_registry import XMLRegistryProcessor
from gpohound.processors.pol_registry import POLRegistryProcessor
from gpohound.processors.privilege_rights import PrivilegeRightsProcessor


class GPOProcessor:
    """
    Process the GPOs settings for analysis
    """

    def __init__(self, ad_utils):
        self.ad_utils = ad_utils

        self.processors = {}
        self.processors["Group Membership"] = GroupMembershipProcessor(ad_utils).process
        self.processors["Groups.xml"] = XMLGroupsProcessor(ad_utils).process
        self.processors["Registry Values"] = RegistryValuesProcessor().process
        self.processors["Registry.xml"] = XMLRegistryProcessor().process
        self.processors["registry.pol"] = POLRegistryProcessor().process
        self.processors["Privilege Rights"] = PrivilegeRightsProcessor(ad_utils).process

    def process(self, gpo_settings, objects, domain_sid):
        """
        Process GPO and group settings that impact the same objects
        """

        # Move the sections of GptTmpl.inf to gpo_settings root
        gptemplate = gpo_settings.get("Machine", {}).get("GptTmpl.inf", {})
        if gptemplate:
            gpo_settings["Machine"].update(gptemplate)
            del gpo_settings["Machine"]["GptTmpl.inf"]

        # Extract settings
        processed_settings = {}
        for config in ["User", "Machine"]:
            for setting_type, setting in gpo_settings.get(config, {}).items():

                if setting:

                    if (not objects or "group" in objects) and setting_type in [
                        "Group Membership",
                        "Groups.xml",
                    ]:
                        processor = self.processors.get(setting_type, domain_sid)
                        output = processor(setting, domain_sid)

                    elif (not objects or "registry" in objects) and setting_type in [
                        "Registry Values",
                        "Registry.xml",
                        "registry.pol",
                    ]:
                        processor = self.processors.get(setting_type)
                        output = processor(setting)

                    elif (not objects or "privilege" in objects) and setting_type == "Privilege Rights":
                        processor = self.processors.get(setting_type)
                        output = processor(setting)
                    else:
                        continue

                    if output and isinstance(output, list):
                        processed_settings.setdefault(config, {}).setdefault(setting_type, []).extend(output)
                    elif output and isinstance(output, dict):
                        processed_settings.setdefault(config, {})[setting_type] = output

        return processed_settings
