import os
import logging
import configparser
from gpohound.utils.utils import load_yaml_config


class INIParser:
    """Parse .ini files"""

    def __init__(self, config="config.gpo_files_structure.ini") -> None:
        self.config = load_yaml_config(config)

    def parse(self, file_path):
        """
        Parses an INI file based on YAML configuration and specific file rules.

        Args:
            file_path (str): Path to the INI file.
            policy_mode (str, optional): 'computer' or 'user' for Scripts.ini and Psscripts.ini modes. Defaults to None.

        Returns:
            dict: Parsed data structured according to the configuration.
        """
        filename = os.path.basename(file_path).lower()

        if filename == "gpt.ini":
            return self._parse_gpt(file_path)
        elif filename == "scripts.ini":
            return self._parse_scripts(file_path)
        elif filename == "psscripts.ini":
            return self._parse_psscripts(file_path)
        else:
            return None

    def _parse_gpt(self, file_path):
        """Parses GPT.ini based on the YAML configuration."""
        output = {}
        ini_parser = configparser.ConfigParser(allow_no_value=True, interpolation=None)

        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="replace") as ini_file:
                ini_lines = [
                    line for line in ini_file if line.strip() and not line.strip().startswith(("#", ";"))
                ]  # Remove comments and empty lines
                ini_parser.read_string("".join(ini_lines))

        except configparser.MissingSectionHeaderError as error:
            logging.debug("Could not read INI file %s: %s", file_path, error)
            return {"GPT.ini": "Could not parse this file"}

        for section, rules in self.config.items():
            if "include" in rules:
                output[section] = {}
                attributes = rules.get("attributes", [])

                for attr in attributes:
                    if attr in ini_parser[section]:  # Only add attributes that exist in the INI file
                        output[section][attr] = ini_parser[section][attr]

        return {"GPT.ini": output}

    def _parse_scripts(self, file_path):
        """Parses Scripts.ini based on Microsoft's 2.2.2 Syntax."""
        valid_sections = ["Startup", "Shutdown", "Logon", "Logoff"]

        ini_parser = configparser.ConfigParser(allow_no_value=True, delimiters=["="], interpolation=None)

        with open(file_path, "r", encoding="utf-16le") as f:
            content = f.read().lstrip("\ufeff")  # Remove BOM if present
            ini_lines = [line for line in content.splitlines() if line.strip()]  # Remove empty lines
            ini_parser.read_string("\n".join(ini_lines))

        output = {}

        for section in ini_parser.sections():
            if section not in valid_sections:
                continue  # Ignore invalid sections

            commands = {}
            for key, value in ini_parser.items(section):
                if key.lower().endswith("cmdline"):
                    index = key[:-7]  # Remove 'CmdLine' to get index
                    cmd_key = f"{index}cmdline"
                    param_key = f"{index}parameters"

                    if cmd_key in ini_parser[section] and param_key in ini_parser[section]:
                        commands[index] = {
                            "CmdLine": ini_parser[section][cmd_key],
                            "Parameters": ini_parser[section][param_key],
                        }

            output[section] = dict(sorted(commands.items()))  # Ensure sorted execution order

        return {"Scripts.ini": output}

    def _parse_psscripts(self, file_path):
        """Parses Psscripts.ini based on Microsoft's 2.2.3 Syntax."""
        valid_sections = [
            "Startup",
            "Shutdown",
            "ScriptsConfig",
            "Logon",
            "Logoff",
            "ScriptsConfig",
        ]

        ini_parser = configparser.ConfigParser(allow_no_value=True, delimiters=["="], interpolation=None)

        with open(file_path, "r", encoding="utf-16le") as f:
            content = f.read().lstrip("\ufeff")  # Remove BOM if present
            ini_lines = [line for line in content.splitlines() if line.strip()]  # Remove empty lines
            ini_parser.read_string("\n".join(ini_lines))

        output = {}

        for section in ini_parser.sections():
            if section not in valid_sections:
                continue  # Ignore invalid sections

            if section == "ScriptsConfig":
                config_settings = {}
                for key, value in ini_parser.items(section):
                    if key in ["startexecutepsfirst", "endexecutepsfirst"]:
                        config_settings[key] = value.lower() == "true"
                if config_settings:
                    output[section] = config_settings
            else:
                commands = {}
                for key, value in ini_parser.items(section):
                    if key.endswith("cmdline"):
                        index = key[:-7]  # Remove 'CmdLine' to get index
                        cmd_key = f"{index}cmdline"
                        param_key = f"{index}parameters"

                        if cmd_key in ini_parser[section] and param_key in ini_parser[section]:
                            commands[index] = {
                                "CmdLine": ini_parser[section][cmd_key],
                                "Parameters": ini_parser[section][param_key],
                            }

                output[section] = dict(sorted(commands.items()))  # Ensure sorted execution order

        return {"PSscripts.ini": output}
