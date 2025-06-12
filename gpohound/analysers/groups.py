import re
import logging
from gpohound.utils.utils import load_yaml_config


class GroupAnalyser:
    """Analyse group memberships"""

    def __init__(self, ad_utils, config="config.analysis", config_file="group.yaml"):
        self.ad_utils = ad_utils
        self.privileged_groups = load_yaml_config(config, config_file)

    def analyse(self, domain_sid, gpo_guid, processed_gpo):
        """
        Analyse group membership and get the following findings :
            - Trustee added to sensitive groups
            - User added to sensitive group on logon
            - Renamed sensitive groups
            - Trustee added to sensitive group and containing "System Defined Variables"
            - Members vulnerable to hijacking
        """
        results = {}

        for policy_type in ["User", "Machine"]:

            output_groups = {}

            for config in ["Groups.xml", "Group Membership"]:
                groups = processed_gpo.get(policy_type, {}).get(config, [])

                # Iterates over groups
                for group in groups:

                    if group:
                        group_sid = group.get("Group").get("sid")

                        # Only analyse group membership that does not remove the group
                        if group_sid in self.privileged_groups and group.get("Action") != "REMOVE":
                            output_groups.setdefault(group_sid, {})["sid"] = group_sid
                            output_groups.setdefault(group_sid, {})["name"] = self.privileged_groups[group_sid]["name"]

                            # Members in privileged group
                            if group.get("Members", {}):

                                output_groups.setdefault(group_sid, {}).setdefault("analysis", set()).add(
                                    f"The following trustees are added to the \"{self.privileged_groups[group_sid]['name']}\" local group."
                                )
                                output_groups.setdefault(group_sid, {}).setdefault("references", set()).add(
                                    self.privileged_groups[group_sid]["edge_reference"]
                                )
                                output_groups.setdefault(group_sid, {})["edge"] = self.privileged_groups[group_sid][
                                    "edge"
                                ]

                                hijackable = set()

                                # Iterates over group members
                                for member in group.get("Members", {}):

                                    # Only if the user is added to the group
                                    if member.get("action") == "ADD":

                                        # Append member
                                        entry = {
                                            "sid": member.get("sid"),
                                            "name": member.get("name"),
                                        }
                                        output_groups.setdefault(group_sid, {}).setdefault("Members", []).append(entry)

                                        # Find System Defined Variables
                                        name = member.get("name") if member.get("name") else ""

                                        if "\\" in name:
                                            member_samaccountname = name.split("\\", 1)[1]
                                        else:
                                            member_samaccountname = name

                                        env_match = re.findall(r"\%(.*?)\%", member_samaccountname)

                                        if env_match:
                                            output_groups[group_sid].setdefault("references", set()).add(
                                                "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789194(v=ws.11)#preference-process-variables"
                                            )

                                            if domain_sid:
                                                supported = True
                                                for var in env_match:
                                                    if not var.lower() == "computername":
                                                        logging.debug("Variable in GPP is not supported")
                                                        supported = False
                                                        break

                                                if supported:

                                                    machines = self.ad_utils.get_machines_affected_by_gpo(
                                                        gpo_guid, domain_sid
                                                    )
                                                    if machines:
                                                        for machine in machines:
                                                            domain = machine.get("domain", "")
                                                            machine_name = machine.get("name", "").replace(
                                                                f".{domain}", ""
                                                            )
                                                            samaccountname = re.sub(
                                                                r"\%computername\%",
                                                                machine_name,
                                                                member_samaccountname,
                                                                flags=re.I,
                                                            )
                                                            member = self.ad_utils.get_trustee(
                                                                samaccountname, domain_sid
                                                            )
                                                            if not member.get("sid"):
                                                                hijackable.add(samaccountname)

                                        # No SID found in processing
                                        elif not member.get("sid") and domain_sid:
                                            hijackable.add(member.get("name"))

                                        # Name-Only with a @ for UPN-type
                                        elif (
                                            domain_sid
                                            and "@" in name
                                            and "\\" not in name
                                            and not self.ad_utils.samaccountname_to_sid(name, domain_sid)
                                        ):
                                            hijackable.add(member.get("name"))

                                if len(hijackable) > 0:
                                    output_groups[group_sid].setdefault("analysis", set()).add(
                                        "Identified sAMAccountName(s) vulnerable to hijacking"
                                    )
                                    output_groups[group_sid].setdefault("references", set()).add(
                                        "https://www.cogiceo.com/en/whitepaper_gpphijacking/"
                                    )
                                    output_groups[group_sid].setdefault("Hijackable", {"lte_20": [], "gt_20": []})
                                    for samaccountname in hijackable:
                                        if len(samaccountname) <= 20:
                                            output_groups[group_sid]["Hijackable"]["lte_20"].append(samaccountname)
                                        else:
                                            output_groups[group_sid]["Hijackable"]["gt_20"].append(samaccountname)

                            # User policy type with logged on user added to the group
                            if policy_type == "User" and group.get("Group").get("useraction") == "ADD":
                                output_groups.setdefault(group_sid, {}).setdefault("analysis", set()).add(
                                    f"Any user who can log on with a fully interactive session will be assigned to the \"{group.get('Group').get('name')}\" local group."
                                )
                                output_groups.setdefault(group_sid, {}).setdefault("references", set()).add(
                                    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/4b6788a7-c106-4e55-9cfc-1a52bb786e86"
                                )

                            # Privileged group being renamed
                            if group.get("Group").get("newname"):
                                output_groups.setdefault(group_sid, {}).setdefault("analysis", set()).add(
                                    f"The privileged group is being renamed to \"{group.get('Group').get('newname')}\""
                                )
                                output_groups.setdefault(group_sid, {}).setdefault("references", set()).add(
                                    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/4b6788a7-c106-4e55-9cfc-1a52bb786e86"
                                )

            # Add findings to the output
            for priv_group_sid, priv_group in output_groups.items():

                if priv_group.get("analysis"):

                    priv_group["analysis"] = "\n\n".join(list(sorted(output_groups[priv_group_sid]["analysis"])))
                    priv_group["references"] = "\n".join(list(sorted(output_groups[priv_group_sid]["references"])))

                    results.setdefault(policy_type, []).append(priv_group)

        return results
