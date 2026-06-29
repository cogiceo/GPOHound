from rich.prompt import Prompt
from rich.prompt import Confirm

from gpohound.utils.utils import load_yaml_config


class ActiveDirectoryUtils:
    """
    Class to interact with AD objects
    """

    def __init__(
        self,
        bloodhound,
        sqlite_handler,
        config="config",
        config_file="well_known_groups.yaml",
    ):
        self.config_trustee = load_yaml_config(config, config_file)
        self.bloodhound = bloodhound
        self.sqlite_handler = sqlite_handler
        self.netbios_names = {}

    def is_sid(self, value):
        """
        Test if the value is a SID
        """
        return value.startswith("*S-1-") or value.startswith("S-1-")

    def sid_to_name(self, sid):
        """
        Convert a SID to a name
        """
        sid = sid.strip("*")
        trustee = next(
            (item for item in self.config_trustee if item["sid"].lower() == sid.lower()),
            None,
        )

        if trustee:
            # Builtin group
            return trustee["displayname"]

        if self.bloodhound.connection:
            # Domain group or user
            node = self.bloodhound.find_by_objectid(sid)

            if node and "samaccountname" in node["n"]:
                return node["n"]["samaccountname"]

        if self.sqlite_handler.dbs:
            result = self.sqlite_handler.find_by_objectid(sid)
            if result:
                return result["sAMAccountName"]

        return None

    def samaccountname_to_sid(self, samaccountname, domain_sid=None):
        """
        Convert a display name to a SID
        """
        # Try to find Builtin groups
        trustee = next(
            (item for item in self.config_trustee if item["displayname"].lower() == samaccountname.lower()),
            None,
        )
        if trustee:
            return trustee["sid"]

        trustee = next(
            (
                item
                for item in self.config_trustee
                if item["displayname"].lower() == ("BUILTIN\\" + samaccountname).lower()
            ),
            None,
        )
        if trustee:
            return trustee["sid"]

        if self.bloodhound.connection and domain_sid:
            node = self.bloodhound.find_by_samaccountname(samaccountname, domain_sid)
            if node and "objectid" in node["n"]:
                return node["n"]["objectid"]

        if self.sqlite_handler.dbs and domain_sid:
            result = self.sqlite_handler.find_by_samaccountname(samaccountname, domain_sid)
            if result:
                return result["objectSid"]

        return None

    def get_all_samaccountnames(self):
        """
        Get all samaccountnames of any domain
        """
        if self.bloodhound.connection:
            nodes = self.bloodhound.all_samaccountnames()
            if nodes:
                return self.bloodhound.nodes_to_dict(nodes)

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.all_samaccountnames()
            if results:
                return results

        return None

    def netbios_to_domain(self, netbios_name):
        """
        Netbios name to a domain name
        """
        netbios_name = netbios_name.upper()
        if netbios_name in self.netbios_names:
            return self.netbios_names.get(netbios_name)
        elif "%" in netbios_name:
            return None
        elif netbios_name in ["NT SERVICE", "NT AUTHORITY"]:
            self.netbios_names.update({netbios_name: None})
            return None
        else:
            domains = self.get_domains()

            if not domains:
                return None

            elif len(domains) == 1:
                domain_name = domains[0]["name"].lower()

                confirm_domain = Confirm.ask(
                    f"[bold][underline]Is [red]{netbios_name}[/red] the NetBIOS name of [green]{domain_name}[/green][/underline][/bold]",
                    default=True,
                )

                if confirm_domain:
                    self.netbios_names.update({netbios_name: domain_name})
                    return domain_name
                else:
                    self.netbios_names.update({netbios_name: None})

            else:
                prompt_string = f"[bold][underline]Enter the domain associated with the NetBIOS name [green]{netbios_name}[/green]:[/underline]\n  0. Not found[/bold]"
                domains_dict = {"0": None}

                for idx, domain in enumerate(domains, start=1):
                    domain_name = domain["name"].lower()
                    domains_dict.update({str(idx): domain_name})
                    prompt_string += f"\n[bold]  {idx}. " + domain_name + "[/bold]"

                domain_idx = Prompt.ask(
                    prompt_string + "\n",
                    choices=domains_dict.keys(),
                    default=None,
                    show_choices=False,
                )

                if domain_idx:
                    output_domain_name = domains_dict.get(domain_idx)
                    self.netbios_names.update({netbios_name: output_domain_name})
                    return output_domain_name
                else:
                    self.netbios_names.update({netbios_name: None})
        return None

    def get_trustee(self, trustee, domain_sid=None):
        """
        Get trustee based on name or sid
        """
        trustee_output = {}
        if trustee:

            # Find based on sid
            if self.is_sid(trustee):
                sid = trustee.strip("*")
                name = self.sid_to_name(sid)

            # Builtin groups
            elif self.samaccountname_to_sid(trustee):
                name = trustee
                sid = self.samaccountname_to_sid(trustee)

            # Find based on domain\trustee or NetBIOS\trustee
            elif "\\" in trustee and not trustee.upper().startswith("BUILTIN\\"):
                sid = None
                name = trustee

                domain, samaccountname = trustee.split("\\", 1)
                domain_sid = self.domain_to_sid(domain)

                # DNS Domain Name
                if domain_sid:
                    sid = self.samaccountname_to_sid(samaccountname, domain_sid)

                # NetBIOS Domain Name
                else:
                    domain_name = self.netbios_to_domain(domain)
                    if domain_name:
                        domain_sid = self.domain_to_sid(domain_name)
                        sid = self.samaccountname_to_sid(samaccountname, domain_sid)

            # Find based on trustee@DnsDomainName (UPN)
            elif "@" in trustee and self.domain_to_sid(trustee.rsplit("@", 1)[1]):
                sid = None
                name = trustee

                samaccountname, domain_dns = trustee.rsplit("@", 1)
                domain_sid = self.domain_to_sid(domain_dns)
                if domain_sid:
                    sid = self.samaccountname_to_sid(samaccountname, domain_sid)

            # Find based on isolated name and domain_sid
            else:
                name = trustee
                sid = self.samaccountname_to_sid(name, domain_sid)

            if sid and name and domain_sid:
                domain = self.find_by_sid(domain_sid)

                if domain:
                    domain_name = domain.get("name")
                    trustee_output["name"] = f"{name}@{domain_name}"
                    trustee_output["sid"] = sid.replace(f"{domain_name.upper()}-", "")
                    trustee_output["domain_sid"] = domain_sid
                    return trustee_output

            else:
                trustee_output["name"] = name
                trustee_output["sid"] = sid
                trustee_output["domain_sid"] = domain_sid
                return trustee_output

        return trustee_output

    def find_by_sid(self, sid, attributes=None):
        """
        Find an object based on it's SID
        """
        sid = sid.strip("*")

        if not sid:
            return None

        if self.bloodhound.connection:
            node = self.bloodhound.find_by_objectid(sid)
            if node:
                return self.bloodhound.node_to_dict(node, attributes)

        if self.sqlite_handler.dbs:
            result = self.sqlite_handler.find_by_objectid(sid)
            if result:
                return result

        return None

    def find_ou(self, target, attributes=None):
        """
        Find OU based on a machine/user or directly a ou
        """
        if self.bloodhound.connection:
            node = self.bloodhound.find_ou(target)
            if node:
                return self.bloodhound.node_to_dict(node, attributes)

        if self.sqlite_handler.dbs:
            result = self.sqlite_handler.find_ou(target)
            if result:
                return result

        return None

    def find_trustee_ou(self, target, attributes=None):
        """
        Find ou based on a machine/user or directly a ou
        """
        if self.bloodhound.connection:
            node = self.bloodhound.find_trustee_ou(target)
            if node:
                return self.bloodhound.node_to_dict(node, attributes)

        if self.sqlite_handler.dbs:
            result = self.sqlite_handler.find_trustee_ou(target)
            if result:
                return result

        return None

    def find_by_gpo_guid(self, guid, domain_sid, attributes=None):
        """
        Find a gpo based on a GUID and makes sure it is not empty
        """
        if self.bloodhound.connection:
            node = self.bloodhound.find_by_gpo_guid(guid, domain_sid)

            if node and "name" in node["n"]:
                output = self.bloodhound.node_to_dict(node, attributes)
                output["name"] = output["name"].rsplit("@", 1)[0]
                return output

        if self.sqlite_handler.dbs:
            result = self.sqlite_handler.find_by_gpo_guid(guid, domain_sid)
            if result:
                return result

        return None

    def get_wmi_filter(self, gpo_guid, domain):
        """
        Find the WMI filters for a GPO
        """
        if self.sqlite_handler.dbs:
            obj = self.sqlite_handler.find_by_domain_name(domain)
            if obj:
                domain_sid = obj.get("objectSid")
                result = self.sqlite_handler.get_wmi_filter(gpo_guid, domain_sid)
                if result:
                    return result

        return None

    def get_deployed_printers(self, domain):
        """
        Find the deployed printers on the domain
        """
        if self.sqlite_handler.dbs:
            obj = self.sqlite_handler.find_by_domain_name(domain)
            if obj:
                domain_sid = obj.get("objectSid")
                result = self.sqlite_handler.get_deployed_printers(domain_sid)
                if result:
                    return result

        return None

    def get_domains(self):
        """
        Find all the domains
        """
        if self.bloodhound.connection:
            results = self.bloodhound.find_domains()
            if results:
                return self.bloodhound.nodes_to_dict(results)

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.find_domains()
            if results:
                return results

        return None

    def domain_to_sid(self, domain):
        """
        Domain name to sid
        """
        if self.bloodhound.connection:
            result = self.bloodhound.find_by_domain_name(domain)
            if result and "objectid" in result["n"]:
                return result["n"]["objectid"]

        if self.sqlite_handler.dbs:
            result = self.sqlite_handler.find_by_domain_name(domain)
            if result:
                return result["objectSid"]

    def gpo_inheritance(self, ou_id):
        """
        Get GPO application order (inheritance)
        """

        if self.bloodhound.connection:
            results = self.bloodhound.get_gpo_inheritance(ou_id)
            if results:
                results = self.bloodhound.nodes_to_dict(results)
                for i in range(len(results)):
                    if hasattr(results[i], "name"):
                        results[i]["name"] = results[i]["name"].rsplit("@", 1)[0]
                return results

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.get_gpo_inheritance(ou_id)
            if results:
                return results

        return None

    def get_gpo_impact(self, gpo_guid, domain_sid):
        """
        Get OUs affected by a GPO as well as the users and computers impacted
        """

        output = {}

        found_ous = self.get_ous_affected_by_gpo(gpo_guid, domain_sid)
        if not found_ous:
            return None

        for ou in found_ous:

            users = self.get_users_in_ou(ou.get("objectid"), domain_sid)
            users_names = [user.get("name") for user in users] if users else []

            machines = self.get_machines_in_ou(ou.get("objectid"), domain_sid)
            machines_names = [machine.get("name") for machine in machines] if machines else []

            if machines_names or users_names:
                output[ou.get("distinguishedname")] = {
                    "Computers": machines_names,
                    "Users": users_names,
                }

        return output or None

    def get_ous(self, domain_sid):
        """
        Get all the ous of a domain
        """

        if self.bloodhound.connection:
            results = self.bloodhound.get_ous(domain_sid)
            if results:
                return self.bloodhound.nodes_to_dict(results)

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.get_ous(domain_sid)
            if results:
                return results

        return None

    def get_ous_affected_by_gpo(self, gpo_guid, domain_sid):
        """
        Get Container, Domain, OU affected by a GPO
        """

        if self.bloodhound.connection:
            results = self.bloodhound.ous_affected_by_gpo(gpo_guid, domain_sid)
            if results:
                return self.bloodhound.nodes_to_dict(results)

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.ous_affected_by_gpo(gpo_guid, domain_sid)
            if results:
                return results

        return None

    def get_machines_in_ou(self, ou_id, domain_sid):
        """
        Get machines in a OU
        """

        if self.bloodhound.connection:
            results = self.bloodhound.machines_in_ou(ou_id, domain_sid)
            if results:
                return self.bloodhound.nodes_to_dict(results)

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.get_obj_in_ou(ou_id, domain_sid, obj_type="computer")
            if results:
                return results

        return None

    def get_users_in_ou(self, ou_id, domain_sid):
        """
        Get users in a OU
        """

        if self.bloodhound.connection:
            results = self.bloodhound.users_in_ou(ou_id, domain_sid)
            if results:
                return self.bloodhound.nodes_to_dict(results)

        if self.sqlite_handler.dbs:
            results = self.sqlite_handler.get_obj_in_ou(ou_id, domain_sid, obj_type="user")
            if results:
                return results

        return None
