import re
import ipaddress
import yaml

from pathlib import Path
from importlib import resources

from platformdirs import user_config_dir

############################### Load config ###############################


def load_yaml_config(config, file_name=None):
    """Load the YAML configuration file."""

    # If a file name is provided only load this configuration file
    if file_name:

        if file_name.endswith(".yaml"):

            # Override configuration file with the one specified in the user's config folder
            override_file = override_configuration(file_name)

            # Load YAML file
            if override_file:
                with override_file.open("r", encoding="utf-8") as file:
                    return yaml.safe_load(file)
            else:
                with resources.files(config).joinpath(file_name).open("r", encoding="utf-8") as file:
                    return yaml.safe_load(file)

    # Else load all the configuration files
    else:
        loaded_config = {}
        for config_file in resources.files(config).iterdir():
            if config_file.name.endswith(".yaml"):

                # Override configuration file with the one specified in the user's config folder
                override_file = override_configuration(config_file.name)
                if override_file:
                    config_file = override_file

                # Load YAML file
                with config_file.open("r", encoding="utf-8") as file:
                    tmp_config = yaml.safe_load(file)

                loaded_config = loaded_config | tmp_config

        return loaded_config


def override_configuration(file_name):
    """
    Override configuration with custom configuration from the user configuration directory
    """

    path = user_config_dir("gpohound")
    files = Path(path).rglob(file_name)

    # Return the first found file path in the user's configuration
    for path in files:
        return path

    return None


############################### Find data functions ###############################


def find_keys_recursive(dictionary, target_keys):
    """
    Find keys in a dictionary
    """

    results = {}
    if isinstance(target_keys, str):
        target_keys = [target_keys]

    def helper(element, path):

        if isinstance(element, dict):
            for key, value in element.items():
                current_path = path + [key]
                if key in target_keys:
                    if key not in results:
                        results[key] = []
                    results[key].append({"path": current_path, "value": value})
                helper(value, current_path)

        elif isinstance(element, list):
            for index, item in enumerate(element):
                current_path = path + [str(index)]
                helper(item, current_path)

    helper(dictionary, [])
    return results


def search_keys_values(data, search_term: str, show=None):
    """
    Search for regex pattern within a nested dictionary.
    """

    matches = {}

    search_pattern = re.compile(search_term, re.IGNORECASE)

    def search_recursive(dictionary, path):

        for key, value in dictionary.items():

            path = [str(p) for p in path]
            current_path = path + [str(key)]

            if search_pattern.search(key):
                if show:
                    matches.setdefault("Paths", []).append({"/".join(current_path): dictionary})
                else:
                    matches.setdefault("Paths", []).append("/".join(current_path))

            if isinstance(value, dict):
                search_recursive(value, current_path)

            elif isinstance(value, list):
                search_in_list(value, current_path)

            elif isinstance(value, str) and path:
                if search_pattern.search(value):
                    if show:
                        matches.setdefault("Values", {})["/".join(path)] = {key: dictionary}
                    else:
                        matches.setdefault("Values", {})["/".join(path)] = {key: value}

    def search_in_list(lst, path):
        for idx, item in enumerate(lst):
            path = [str(p) for p in path]
            current_path = path + [str(idx)]
            if isinstance(item, dict):
                search_recursive(item, current_path)
            elif isinstance(item, list):
                search_in_list(item, current_path)
            elif isinstance(item, str):
                if search_pattern.search(item) and path:
                    if show:
                        matches.setdefault("Values", {})["/".join(path)] = lst
                    else:
                        matches.setdefault("Values", {})["/".join(path)] = item

    search_recursive(data, [])

    return matches


############################### Utils ###############################


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
