from rich.prompt import Prompt
from rich.prompt import Confirm

from gpohound.utils.utils import load_yaml_config


class ActiveDirectoryUtils:
    """
    Class to interact with AD objects
    """

    def __init__(
        self,
        bloodhound_connector,
        config="config",
        config_file="well_known_groups.yaml",
    ):
        self.config_trustee = load_yaml_config(config, config_file)
        self.bloodhound = bloodhound_connector
        self.netbios_names = {}

    def node_to_dict(self, query_result, attributes=None):
        """
        Convert a bloodhound node "n" to a dictionary
        """
        node_dict = dict(query_result["n"])
        if attributes:
            extract = {}
            for attribute in attributes:
                extract.update({attribute: node_dict.get(attribute)})
            node_dict = extract
        return node_dict

    def nodes_to_dict(self, query_results):
        """
        Convert multiples BloodHound node to a dictionary list
        """
        if len(query_results) == 1:
            return [self.node_to_dict(query_results)]
        else:
            return [self.node_to_dict(result) for result in query_results]

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

        elif self.bloodhound.connection:
            # Domain group or user
            node = self.bloodhound.find_by_objectid(sid)

            if node and "samaccountname" in node["n"]:
                return node["n"]["samaccountname"]

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

        else:
            domains = self.get_domains()

            if not domains:
                return None

            elif len(domains) == 1:
                domain_name = domains[0]["name"].lower()
                confirm_domain = Confirm.ask(
                    f"[bold][underline]Is [red]{netbios_name}[/red] the NetBIOS name of [green]{domain_name}[/green][/underline][/bold]",
                    default=False,
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

                (
                    samaccountname,
                    domain_dns,
                ) = trustee.rsplit("@", 1)
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

        if self.bloodhound.connection:
            node = self.bloodhound.find_by_objectid(sid)
            return self.node_to_dict(node, attributes)

        return None

    def find_container(self, target, attributes=None):
        """
        Find container based on a machine/user or directly a container
        """
        if self.bloodhound.connection:
            node = self.bloodhound.find_container(target)
            if node:
                return self.node_to_dict(node, attributes)
        return None

    def find_trustee_container(self, target, attributes=None):
        """
        Find container based on a machine/user or directly a container
        """
        if self.bloodhound.connection:
            node = self.bloodhound.find_trustee_container(target)
            if node:
                return self.node_to_dict(node, attributes)
        return None

    def find_by_gpo_guid(self, guid, domain_sid, attributes=None):
        """
        Find a gpo based on a GUID and makes sure it is not empty
        """
        if self.bloodhound.connection:
            node = self.bloodhound.find_by_gpo_guid(guid, domain_sid)

            if node and "name" in node["n"]:
                output = self.node_to_dict(node, attributes)

                if "name" in output:
                    output["name"] = output["name"].rsplit("@", 1)[0]

                return output

        return None

    def get_domains(self):
        """
        Find all the domains
        """
        if self.bloodhound.connection:
            results = self.bloodhound.find_domains()
            if results:
                return self.nodes_to_dict(results)

        return None

    def domain_to_sid(self, domain):
        """
        Domain name to sid
        """
        if self.bloodhound.connection:
            result = self.bloodhound.find_by_domain_name(domain)
            if result and "objectid" in result["n"]:
                return result["n"]["objectid"]

    def container_inheritance(self, container_id):
        """
        Get GPO application order (inheritance)
        """

        if self.bloodhound.connection:
            gpo_inheritance = self.bloodhound.get_gpo_inheritance(container_id)
            if gpo_inheritance:
                return self.nodes_to_dict(gpo_inheritance)

        return None

    def get_containers(self, domain_sid):
        """
        Get all the containers of a domain
        """

        if self.bloodhound.connection:
            results = self.bloodhound.get_containers(domain_sid)
            if results:
                return self.nodes_to_dict(results)

        return None

    def get_containers_affected_by_gpo(self, gpo_guid, domain_sid):
        """
        Get containers (Domain, OU, Container) affected by a GPO
        """

        if self.bloodhound.connection:
            results = self.bloodhound.containers_affected_by_gpo(gpo_guid, domain_sid)
            if results:
                return self.nodes_to_dict(results)

        return None

    def get_machines_affected_by_gpo(self, gpo_guid, domain_sid):
        """
        Get machines affected by a GPO
        """

        if self.bloodhound.connection:
            results = self.bloodhound.machines_affected_by_gpo(gpo_guid, domain_sid)
            if results:
                return self.nodes_to_dict(results)

        return None

    def resolve_gpo_name(self, domainpolicies):
        """
        Resolves the GPO names
        """
        for domain, gpos in domainpolicies.items():
            domain_sid = self.domain_to_sid(domain)
            if domain_sid:
                guids = list(gpos.keys())
                for guid in guids:
                    gpo = self.find_by_gpo_guid(guid, domain_sid)
                    if gpo:
                        # Move Name to the top of the dictionary
                        gpo_with_name = {"GPO Name": gpo.get("name")}
                        gpo_with_name.update(domainpolicies[domain][guid])
                        domainpolicies[domain][guid] = gpo_with_name
        return domainpolicies
