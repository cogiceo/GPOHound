import re
import logging
from gpohound.utils.utils import load_yaml_config


class GroupAnalyser:
    """Analyse group memberships"""

    def __init__(self, ad_utils, config="config.analysis", config_file="group.yaml"):
        self.ad_utils = ad_utils
        self.privileged_groups = load_yaml_config(config, config_file)
        self.container_machines = {}
        self.samaccountname_sid = None
        self.all_samaccountnames = None

    def get_hijackable(self, env_match, member_name, gpo_guid, domain_sid):
        """
        Return potentially hijackable sAMAccountName
        """

        hijackable = set()
        env_members = []

        # Variable in the name
        if env_match:
            for var in env_match:
                if var.lower() == "computername":

                    # Get container affected by the GPO
                    containers = self.ad_utils.get_containers_affected_by_gpo(gpo_guid, domain_sid) or []

                    # Get machines names affected by the GPO
                    machines_names = []
                    for container in containers:
                        if not container.get("objectid") in self.container_machines:
                            self.container_machines[container.get("objectid")] = []
                            container_machines = (
                                self.ad_utils.get_machines_in_container(container.get("objectid"), domain_sid) or []
                            )

                            for machine in container_machines:
                                self.container_machines[container.get("objectid")].append(
                                    machine.get("samaccountname", "")
                                )

                        machines_names.extend(self.container_machines[container.get("objectid")])

                    # Check if the resolved name exists for each machine
                    for machine_name in machines_names:
                        samaccountname = re.sub(
                            r"\%computername\%",
                            machine_name.strip("$"),
                            member_name,
                            flags=re.I,
                        )

                        if self.all_samaccountnames is None:
                            self.all_samaccountnames = set()
                            results = self.ad_utils.get_all_samaccountnames()
                            if results:
                                self.samaccountname_sid = {
                                    object["samaccountname"].upper(): object["objectid"].upper() for object in results
                                }
                                self.all_samaccountnames = set(self.samaccountname_sid.keys())

                        if not samaccountname.upper() in self.all_samaccountnames:
                            hijackable.add(samaccountname)
                        else:
                            entry = {
                                "sid": self.samaccountname_sid.get(samaccountname.upper(), ""),
                                "name": samaccountname,
                                "computer_sid": self.samaccountname_sid.get(machine_name.upper(), ""),
                                "computer_name": machine_name,
                            }
                            env_members.append(entry)
                else:
                    logging.debug(f"Variable %{var}% in GPP is not supported")

        # Name-Only with a @ for UPN-type
        elif "@" in member_name and not self.ad_utils.samaccountname_to_sid(member_name, domain_sid):
            hijackable.add(member_name)

        # SID not resolved during processing
        else:
            hijackable.add(member_name)

        if hijackable:
            output = {"lte_20": [], "gt_20": []}
            for name in hijackable:
                if len(name) <= 20:
                    output["lte_20"].append(name)
                else:
                    output["gt_20"].append(name)
            return output, env_members

        return None, None

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

            output = {}
            for config in ["Groups.xml", "Group Membership"]:
                groups = processed_gpo.get(policy_type, {}).get(config, [])

                # Iterates over groups
                for group in groups:

                    if group:
                        group_sid = group.get("Group").get("sid")

                        # Only analyse group membership that does not remove the group
                        if group_sid in self.privileged_groups and group.get("Action") != "REMOVE":
                            output.setdefault(group_sid, {})["sid"] = group_sid
                            output[group_sid]["name"] = self.privileged_groups[group_sid]["name"]

                            # Members in privileged group
                            if group.get("Members", {}):

                                output[group_sid].setdefault("analysis", set()).add(
                                    f"The following trustees are added to the \"{self.privileged_groups[group_sid]['name']}\" local group."
                                )
                                output[group_sid].setdefault("references", set()).add(
                                    "" + self.privileged_groups[group_sid]["edge_reference"]
                                )
                                output[group_sid]["edge"] = self.privileged_groups[group_sid]["edge"]

                                # Iterates over group members
                                for member in group.get("Members", {}):

                                    # Only if the user is added to the group
                                    if member.get("action") == "ADD":

                                        # Append member
                                        entry = {
                                            "sid": member.get("sid"),
                                            "name": member.get("name"),
                                        }
                                        output[group_sid].setdefault("Members", []).append(entry)

                                        # Find System Defined Variables
                                        name = member.get("name") if member.get("name") else ""

                                        if "\\" in name:
                                            member_name = name.split("\\", 1)[1]
                                        else:
                                            member_name = name

                                        env_match = re.findall(r"\%(.*?)\%", member_name)
                                        if env_match:
                                            output[group_sid]["references"].add(
                                                "https://www.cogiceo.com/en/whitepaper_gpphijacking/"
                                            )

                                        if not member.get("sid") and domain_sid:
                                            hijackable, env_members = self.get_hijackable(
                                                env_match, member_name, gpo_guid, domain_sid
                                            )

                                            if env_members:
                                                output[group_sid]["EnvMembers"] = env_members

                                            if hijackable:
                                                output[group_sid]["analysis"].add(
                                                    "Potentially hijackable sAMAccountName(s) if not linked to local account(s)."
                                                )
                                                output[group_sid]["references"].add(
                                                    "https://www.cogiceo.com/en/whitepaper_gpphijacking/"
                                                )
                                                output[group_sid]["Hijackable"] = hijackable

                            # User policy type with logged on user added to the group
                            if policy_type == "User" and group.get("Group").get("useraction") == "ADD":
                                output[group_sid].setdefault("analysis", set()).add(
                                    f"Any user who can log on with a fully interactive session will be assigned to the \"{group.get('Group').get('name')}\" local group."
                                )
                                output[group_sid].setdefault("references", set()).add(
                                    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/4b6788a7-c106-4e55-9cfc-1a52bb786e86"
                                )

                            # Privileged group being renamed
                            if group.get("Group").get("newname"):
                                output[group_sid].setdefault("analysis", set()).add(
                                    f"The privileged group is being renamed to \"{group.get('Group').get('newname')}\""
                                )
                                output[group_sid].setdefault("references", set()).add(
                                    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/4b6788a7-c106-4e55-9cfc-1a52bb786e86"
                                )

            # Add findings to the output
            for priv_group_sid, priv_group in output.items():

                if priv_group.get("analysis"):
                    priv_group["analysis"] = "\n".join(list(sorted(output[priv_group_sid]["analysis"])))
                    priv_group["references"] = "\n".join(list(sorted(output[priv_group_sid]["references"])))

                    results.setdefault(policy_type, []).append(priv_group)

        return results
