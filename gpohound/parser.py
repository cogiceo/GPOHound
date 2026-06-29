import re
import logging

from os import walk
from pathlib import Path

from gpohound.parsers.xml_files import XMLParser
from gpohound.parsers.pol_files import POLParser
from gpohound.parsers.inf_files import INFParser
from gpohound.parsers.ini_files import INIParser
from gpohound.parsers.csv_files import CSVParser
from gpohound.parsers.aas_files import AASParser
from gpohound.parsers.raw_files import RAWParser


class GPOParser:
    """
    Class to parse data in GPOs
    """

    def __init__(self, selected_policies):

        self.selected_policies = [file.lower() for file in selected_policies]
        self.scripts_folder = ["Startup", "Shutdown", "Logon", "Logoff"]

        self.xmlparser = XMLParser()
        self.polparser = POLParser()
        self.infparser = INFParser()
        self.iniparser = INIParser()
        self.csvparser = CSVParser()
        self.aasparser = AASParser()
        self.rawparser = RAWParser()

    def get_files_info(self, policy_path):
        """
        Get informations on the files to parse for a GPO
        """

        files_info = []

        # Walk through the directories to find files
        for root, _, files in walk(policy_path):
            root = Path(root)

            for file in files:

                full_path = root / file
                parts = full_path.parts

                if file.lower() in self.selected_policies:
                    files_info.append(self.file_info(root, policy_path, file))

                elif (
                    ("scripts.ini" in self.selected_policies or "PSscripts.ini" in self.selected_policies)
                    and parts[-3] == "Scripts"
                    and parts[-2] in self.scripts_folder
                ):
                    script = self.file_info(root, policy_path, file)
                    if script:
                        script["type"] = parts[-2]
                        files_info.append(script)

                elif (
                    "{guid}.aas" in self.selected_policies
                    and file.lower().endswith(".aas")
                    and parts[-2].lower() == "applications"
                    and parts[-3].lower() in ["machine", "user"]
                ):
                    files_info.append(self.file_info(root, policy_path, file))

        return files_info

    def file_info(self, root, policy_path, file):
        """
        Get information on the file in the file system
        """

        full_path = root / file
        relative_path = full_path.relative_to(policy_path)
        relative_parts = {p.lower() for p in relative_path.parts}

        if "machine" in relative_parts:
            policy_type = "Machine"
        elif "user" in relative_parts:
            policy_type = "User"
        else:
            policy_type = ""

        entry = {
            "name": full_path.stem,
            "extension": full_path.suffix,
            "relative_path": relative_path.as_posix(),
            "policy_type": policy_type,
            "full_path": str(full_path),
            "size": f"{full_path.stat().st_size} bytes",
        }

        return entry

    def find_policy_info(self, sysvol_path):
        """
        Built a dictionary of files to be parsed by domain and GPO GUID
        """

        policy_info = {}
        # Regular expression to match the GUID pattern inside /Policies/
        pattern = re.compile(r"(.*?/([^/]+)/Policies/(\{[0-9A-Fa-f-]{36}\}))$")

        # Walk through the directories
        for dirpath, dirnames, _ in walk(sysvol_path):

            dirpath = Path(dirpath)
            for dirname in dirnames:

                full_path = dirpath / dirname
                match_path = pattern.search(full_path.as_posix())

                # Get file path that match the pattern
                if match_path:
                    policy_path = match_path.group(1)
                    domain = match_path.group(2).lower()
                    guid = match_path.group(3).upper()
                    files = self.get_files_info(policy_path)

                    # Store the files path by domain and GPO guids
                    policy_info.setdefault(domain, {}).update({guid: {"path": policy_path, "files": files}})

        return policy_info

    def parse_domains_policies(self, sysvol_path, ad_utils, filter_domains=None, filter_guids=None):
        """
        Extract settings from SYSVOL and LDAP to dictionary
        """

        results = {}
        domain_policies_info = self.find_policy_info(sysvol_path)
        for domain, policies_info in domain_policies_info.items():
            if not filter_domains or domain in filter_domains:
                # SYSVOL files
                for policy_guid, policy_data in policies_info.items():
                    policy_guid = policy_guid.upper()

                    if not filter_guids or policy_guid in filter_guids:
                        policy = self.parse_policy(policy_guid, policy_data)
                        if policy:
                            wmi_filter = ad_utils.get_wmi_filter(policy_guid, domain)
                            if wmi_filter:
                                policy[policy_guid]["WMI filter"] = wmi_filter
                            results.setdefault(domain.lower(), {}).update(policy)

                # Printers in LDAP
                if "ldap_printers" in self.selected_policies:
                    printers = ad_utils.get_deployed_printers(domain)
                    if printers:
                        entry = {}
                        for p in printers:
                            if not filter_guids or p.get("gpoCN") in filter_guids:
                                gpo_entry = entry.setdefault(p.get("gpoCN"), {})
                                printer_section = gpo_entry.setdefault(p.get("gpoType"), {}).setdefault(
                                    "Deployed Printer Connection", {}
                                )
                                printer_section.setdefault("uNCName", []).append(p.get("uNCName"))

                        if entry:
                            results[domain].update(entry)

        return results

    def parse_file(self, policy_file):
        """
        Parse a GPO file based on its extension
        """

        configuration = {}
        extension = policy_file["extension"].lower()

        # Parse file based on file extension
        try:
            match extension:
                case ".xml":
                    configuration = self.xmlparser.parse(policy_file["full_path"])
                case ".pol":
                    configuration = self.polparser.parse(policy_file["full_path"], policy_file["policy_type"])
                case ".inf":
                    configuration = self.infparser.parse(policy_file["full_path"], policy_file["name"])
                case ".ini":
                    configuration = self.iniparser.parse(policy_file["full_path"])
                case ".csv":
                    configuration = self.csvparser.parse(policy_file["full_path"])
                case ".aas":
                    configuration = self.aasparser.parse(policy_file["full_path"], policy_file["name"])
                case _:
                    if policy_file.get("type") in self.scripts_folder and not policy_file.get("extension") in [".exe"]:
                        configuration = self.rawparser.decode_raw_file(policy_file)

        except (UnicodeError, UnicodeDecodeError) as error:
            logging.debug(f"Could not decode file {policy_file['full_path']}: {error}")
            configuration = {policy_file["relative_path"]: "Could not decode this file"}

        if not configuration:
            configuration = {policy_file["relative_path"]: "Empty or invalid configuration"}

        return configuration

    def parse_policy(self, policy_guid, policy_data):
        """
        Parse all the files in a GPO to dictionary
        """

        results = {}

        if not policy_data["files"]:
            return None

        # Iterates over the files in a GPO
        for policy_file in policy_data["files"]:

            configuration = self.parse_file(policy_file)

            if configuration:
                if policy_file["extension"].lower() == ".aas":
                    results.setdefault(policy_file["policy_type"], {}).setdefault(
                        "Application Advertise Script", {}
                    ).update(configuration)
                elif configuration and policy_file["policy_type"] in ["Machine", "User"]:
                    results.setdefault(policy_file["policy_type"], {}).update(configuration)
                else:
                    results = configuration

        return {policy_guid: results}
