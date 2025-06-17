import os
import re
import logging

from gpohound.parsers.xml_files import XMLParser
from gpohound.parsers.pol_files import POLParser
from gpohound.parsers.inf_files import INFParser
from gpohound.parsers.ini_files import INIParser
from gpohound.parsers.csv_files import CSVParser
from gpohound.parsers.aas_files import AASParser


class GPOParser:
    """
    Class to parse the files contain in the Policies
    """

    def __init__(self, policy_files):

        self.policy_files = [file.lower() for file in policy_files]
        self.scripts_folder = ["Startup", "Shutdown", "Logon", "Logoff"]

        self.xmlparser = XMLParser()
        self.polparser = POLParser()
        self.infparser = INFParser()
        self.iniparser = INIParser()
        self.csvparser = CSVParser()
        self.aasparser = AASParser()

        self.domain_policies_info = {}
        self.policies = {}

    def get_files_info(self, policy_path):
        """
        Get informations on the files to parse for a GPO
        """

        files_info = []

        # Walk through the directories to find files
        for root, _, files in os.walk(policy_path):
            for file in files:
                path = [items for items in os.path.join(root, file).split(os.sep)]
                if file.lower() in self.policy_files:
                    files_info.append(self.file_info(root, policy_path, file))
                elif (
                    ("scripts.ini" in self.policy_files or "PSscripts.ini" in self.policy_files)
                    and path[-3] == "Scripts"
                    and path[-2] in self.scripts_folder
                ):
                    script = self.file_info(root, policy_path, file)
                    if script:
                        script["type"] = path[-2]
                        files_info.append(script)
                elif (
                    "{guid}.aas" in self.policy_files
                    and file.lower().endswith(".aas")
                    and path[-2].lower() == "applications"
                    and path[-3].lower() in ["machine", "user"]
                ):
                    files_info.append(self.file_info(root, policy_path, file))

        return files_info

    def file_info(self, root, policy_path, file):
        """
        Get information on the file in the file system
        """

        # Retrive information on the file
        full_path = os.path.join(root, file)
        relative_path = full_path.replace(policy_path, "")
        relative_path_list = [items.lower() for items in relative_path.split(os.sep)]
        policy_type = ""

        if "machine" in relative_path_list:
            policy_type = "Machine"
        elif "user" in relative_path_list:
            policy_type = "User"

        size = os.path.getsize(full_path)
        file_name, file_extension = os.path.splitext(file)

        # Store GPO file information
        entry = {
            "name": file_name,
            "extension": file_extension,
            "relative_path": relative_path,
            "policy_type": policy_type,
            "full_path": full_path,
            "size": f"{size} bytes",
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
        for dirpath, dirnames, _ in os.walk(sysvol_path):

            for dirname in dirnames:
                full_path = os.path.join(dirpath, dirname)
                match_path = pattern.search(full_path)

                # Get file path that match the pattern
                if match_path:
                    policy_path = match_path.group(1)
                    domain = match_path.group(2)
                    guid = match_path.group(3)
                    files = self.get_files_info(policy_path)

                    # Store the files path by domain and GPO guids
                    policy_info.setdefault(domain, {}).update({guid: {"path": policy_path, "files": files}})

        return policy_info

    def parse_domain_policies(self, sysvol_path):
        """
        Extract settings from SYSVOL to dictionary
        """
        results = {}
        domain_policies_info = self.find_policy_info(sysvol_path)
        for domain, policies_info in domain_policies_info.items():
            for policy_guid, policy_data in policies_info.items():
                policy = self.parse_policy(policy_guid, policy_data)
                if policy:
                    results.setdefault(domain.lower(), {}).update(policy)
        if results:
            self.policies.update(results)

    def parse_policy(self, policy_guid, policy_data):
        """
        Parse all the files in a GPO to dictionary
        """
        results = {}

        if not policy_data["files"]:
            return None

        # Iterates over the files in a GPO
        for policy_file in policy_data["files"]:

            configuration = {}
            extension = policy_file["extension"].lower()

            # Parse file based on file extension
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
                    if configuration:
                        results.setdefault(policy_file["policy_type"], {}).setdefault(
                            "Application Advertise Script", {}
                        ).update(configuration)
                        continue
                case _:
                    if policy_file.get("type") in self.scripts_folder:
                        try:
                            raw = open(policy_file["full_path"], "r", encoding="utf-8").read()
                            configuration = {
                                policy_file.get("type"): {
                                    "file": policy_file["relative_path"],
                                    "content": raw,
                                }
                            }
                        except UnicodeDecodeError as error:
                            logging.debug("Could not decode file : %s", error)
                        except FileNotFoundError as error:
                            logging.debug("File not found : %s", error)
                            continue

            if configuration and policy_file["policy_type"] in ["Machine", "User"]:
                results.setdefault(policy_file["policy_type"], {}).update(configuration)
            elif configuration:
                results = configuration

        return {policy_guid.upper(): results}
