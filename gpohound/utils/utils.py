import re
from pathlib import Path
from importlib import resources

import yaml

from rich.tree import Tree
from rich.table import Table
from rich.console import Group
from rich.console import Console
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


############################### Dictionary operation ###############################


def merge_nested_dicts(d1, d2):
    """
    Merge two Dictionaries and list merge nested list
    """
    result = d1.copy()
    for key, value in d2.items():
        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_nested_dicts(result[key], value)
            elif isinstance(result[key], list) and isinstance(value, list):
                result[key].extend(value)
            else:
                result[key] = value  # Overwrite if not both dicts/lists
        else:
            result[key] = value
    return result


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


############################### Printing functions ###############################


def table_output_width():
    """
    Get the current terminal width for table output
    """
    table_width = Console().size.width

    if table_width - 20 > 1:
        table_width -= 20

    return table_width


def print_dict_as_tree(label, dictionary):
    """
    Recursively builds and prints a tree representation of the nested dictionary.
    """

    def dict_to_tree(data, parent, depth=0):
        for key, value in data.items():

            if isinstance(value, list):
                list_tree = None

                for i, item in enumerate(value):

                    if isinstance(item, dict):
                        item_tree = parent.add(f"[bold blue]{key} {i+1} [/bold blue]")
                        dict_to_tree(item, item_tree, depth + 1)
                    else:
                        if not list_tree:
                            if depth == 0:
                                list_tree = parent.add(f"[bold red]{key} [/bold red]")
                            else:
                                list_tree = parent.add(f"[bold blue]{key} [/bold blue]")
                        list_tree.add(f"[bold]{item} [/bold]")

            elif isinstance(value, dict):

                if depth == 0:
                    node = parent.add(f"[bold red]{key} [/bold red]")
                elif depth == 1:
                    key = key.split(":", 1)
                    if len(key) == 2:
                        node = parent.add(f"[bold blue]{key[0]} [/bold blue]:[bold cyan]{key[1]} [/bold cyan]")
                    else:
                        node = parent.add(f"[bold blue]{key[0]} [/bold blue]")
                else:
                    node = parent.add(f"[bold blue]{key} [/bold blue]")
                dict_to_tree(value, node, depth + 1)

            else:
                parent.add(f"[bold blue]{key} [/bold blue]: [bold]{value} [/bold]")

    tree = Tree(label=f"[bold]{label} [/bold]")
    dict_to_tree(dictionary, tree)
    console = Console()
    console.print(tree)


def print_processed(processed_settings):
    """
    Print processed and builds tables for each settings.
    """

    def processed_to_tree(data, parent, depth=0):
        for key, value in data.items():

            if key in ["Registry Values", "registry.pol", "Registry.xml"]:
                node = parent.add(f"[bold blue]{key} [/bold blue]")
                mapping = {
                    "HKEY_CURRENT_USER": "HKCU",
                    "HKEY_USERS": "HKU",
                    "HKEY_LOCAL_MACHINE": "HKLM",
                    "HKEY_CLASSES_ROOT": "HKCR",
                    "HKEY_CURRENT_CONFIG": "HKCC",
                }
                table_registry = Table(show_lines=True, width=int(table_output_width() * 0.90))
                table_registry.add_column("Action", width=8, justify="center")
                table_registry.add_column("Type", width=13, justify="center")
                table_registry.add_column("Hive", width=4, justify="center")
                table_registry.add_column("Key", ratio=6, justify="center", overflow="fold")
                table_registry.add_column("Data", ratio=4, justify="center", overflow="fold")

                for registry in value:
                    table_registry.add_row(
                        registry.get("Action"),
                        registry.get("Type"),
                        mapping.get(registry.get("Hive")),
                        registry.get("Key"),
                        registry.get("Data"),
                    )

                node.add(table_registry)

            elif key == "Privilege Rights":
                node = parent.add(f"[bold blue]{key} [/bold blue]")

                for priv_key, priv_trustees in value.items():
                    priv_node = node.add(f"[bold blue]{priv_key} [/bold blue]")
                    table_priv = Table(show_lines=True, width=int(table_output_width() * 0.60))
                    table_priv.add_column("SID", ratio=1, justify="center")
                    table_priv.add_column("Name", ratio=1, justify="center")
                    for trustee in priv_trustees:
                        table_priv.add_row(trustee.get("sid"), trustee.get("name"))
                    priv_node.add(table_priv)

            elif key in ["Groups.xml", "Group Membership"]:

                for idx, group in enumerate(value, start=1):
                    node = parent.add(f"[bold blue]{key} {idx}[/bold blue]")
                    group_info = group.get("Group", {})

                    args = [
                        group_info.get("name"),
                        group_info.get("sid"),
                        group.get("Action"),
                        str(group.get("DeleteUsers")),
                        str(group.get("DeleteGroups")),
                    ]

                    table_group = Table(show_lines=True, width=int(table_output_width() * 0.7))
                    table_group.add_column("Name", justify="center")
                    table_group.add_column("SID", justify="center")
                    table_group.add_column("Action", width=8, justify="center")
                    table_group.add_column("Delete Users", width=12, justify="center")
                    table_group.add_column("Delete Groups", width=13, justify="center")

                    if group_info.get("useraction"):
                        table_group.add_column("User Action", justify="center")
                        args.append(group_info.get("useraction"))
                    if group_info.get("newname"):
                        table_group.add_column("New Name", justify="center")
                        args.append(group_info.get("newname"))

                    table_group.add_row(*args)

                    if group.get("Members", []):

                        table_members = Table(show_lines=True, expand=True)
                        table_members.add_column("Action", width=8, justify="center")
                        table_members.add_column("SID", ratio=10, justify="center")
                        table_members.add_column("Name", ratio=8, justify="center")

                        for member in group.get("Members", []):
                            table_members.add_row(
                                member.get("action"),
                                member.get("sid"),
                                member.get("name"),
                            )

                        main_members = Table(
                            show_lines=True,
                            width=int(table_output_width() * 0.7),
                            show_header=False,
                        )
                        main_members.add_column("Key", width=7, justify="center", style="bold")
                        main_members.add_column("Value", ratio=1, justify="center")
                        main_members.add_row("Members", table_members)
                        node.add(Group(table_group, main_members))
                    else:
                        node.add(table_group)

            elif isinstance(value, list):
                list_tree = None
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        item_tree = parent.add(f"[bold blue]{key} {i+1} [/bold blue]")
                        processed_to_tree(item, item_tree, depth + 1)
                    else:
                        if not list_tree:
                            list_tree = parent.add(f"[bold blue]{key} [/bold blue]")
                        list_tree.add(f"[bold]{item} [/bold]")

            elif isinstance(value, dict):
                if depth == 0:
                    node = parent.add(f"[bold red]{key} [/bold red]")
                else:
                    node = parent.add(f"[bold blue]{key} [/bold blue]")
                processed_to_tree(value, node, depth + 1)
            else:
                parent.add(f"[bold blue]{key} [/bold blue]: [bold]{value} [/bold]")

    tree = Tree("[bold]Processed GPOs [/bold]")
    processed_to_tree(processed_settings, tree, depth=0)
    console = Console()
    console.print(tree)


def print_analysed(analysed):
    """
    Print analysis and builds tables for each settings.
    """

    def analysed_to_tree(data, parent, depth=0):
        for key, value in data.items():

            if key == "Affected Containers":

                node = parent.add("[bold blue]Affected Containers [/bold blue]")
                table_container = Table(show_lines=True)
                table_container.add_column("Containers")

                for container in value:
                    table_container.add_row(container)

                node.add(table_container)

            elif key == "Registry":

                registry_node = parent.add("[bold blue]Registries [/bold blue]")

                for policy_type, gpo_group in value.items():

                    node = registry_node.add(f"[bold blue]{policy_type} [/bold blue]")

                    for registry in gpo_group:
                        table_registry = Table(show_lines=True, width=int(table_output_width() * 0.75))
                        table_registry.add_column("Analysis", width=12, justify="center", style="bold")
                        table_registry.add_column(registry.get("analysis"), ratio=1, overflow="fold")

                        table_registry.add_row("RegKey", registry.get("regkey"))
                        table_registry.add_row("Value", registry.get("value"))

                        if "VNC Password" in registry:
                            table_registry.add_row("VNC Password", registry.get("VNC Password"))

                        node.add(table_registry)

            elif key == "Privilege Rights":

                priv_node = parent.add("[bold blue]Privilege Rights [/bold blue]")

                for policy_type, data in value.items():

                    node = priv_node.add(f"[bold blue]{policy_type} [/bold blue]")

                    for priv_data in data.values():

                        # Tables for trustees
                        table_trustees = Table(show_lines=True, expand=True)
                        table_trustees.add_column("SID", ratio=10, justify="center")
                        table_trustees.add_column("Name", ratio=8, justify="center")

                        for member in priv_data.get("trustees", []):
                            table_trustees.add_row(member.get("sid"), member.get("name"))

                        # Table for analysis
                        table_privilege = Table(show_lines=True, width=int(table_output_width() * 0.79))
                        table_privilege.add_column("Analysis", width=10, justify="center", style="bold")
                        table_privilege.add_column(priv_data.get("analysis"), ratio=1, overflow="fold")

                        # Add values
                        table_privilege.add_row("Trustees", table_trustees)
                        table_privilege.add_row("References", priv_data.get("references"))

                        node.add(table_privilege)

            elif key == "Groups":

                groups_node = parent.add("[bold blue]Groups [/bold blue]")

                for policy_type, gpo_group in value.items():

                    node = groups_node.add(f"[bold blue]{policy_type} [/bold blue]")

                    for group in gpo_group:

                        # Tables for members
                        table_members = Table(show_lines=True, expand=True)
                        table_members.add_column("SID", ratio=10, justify="center")
                        table_members.add_column("Name", ratio=8, justify="center")

                        for member in group.get("Members", []):
                            table_members.add_row(member.get("sid"), member.get("name"))

                        # Table for analysis
                        table_group = Table(show_lines=True, width=int(table_output_width() * 0.85))
                        table_group.add_column("Analysis", width=10, justify="center", style="bold")
                        table_group.add_column(group.get("analysis"), ratio=1, overflow="fold")

                        # Add values
                        if group.get("Members"):
                            table_group.add_row("Members", table_members)
                        table_group.add_row("References", group.get("references"))

                        node.add(table_group)

            elif key == "GPP Password":

                gpppassword_node = parent.add("[bold blue]GPP Password [/bold blue]")

                for path, passwords in value.items():

                    node = gpppassword_node.add(f"[bold blue]{path} [/bold blue]")

                    table_password = Table(show_lines=True, width=int(table_output_width() * 0.79))
                    table_password.add_column("Decrypted", width=10, justify="center", style="bold")
                    table_password.add_column(passwords.get("decrypted"), ratio=1, overflow="fold")
                    table_password.add_row("Encrypted", passwords.get("encrypted"))

                    node.add(table_password)

            elif isinstance(value, list):
                list_tree = None
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        item_tree = parent.add(f"[bold blue]{key} {i+1} [/bold blue]")
                        analysed_to_tree(item, item_tree, depth + 1)
                    else:
                        if not list_tree:
                            list_tree = parent.add(f"[bold blue]{key} [/bold blue]")
                        list_tree.add(f"[bold]{item} [/bold]")

            elif isinstance(value, dict):
                if depth == 0:
                    node = parent.add(f"[bold red]{key} [/bold red]")  # Domain Name
                else:
                    node = parent.add(f"[bold blue]{key} [/bold blue]")  # Normal Key
                analysed_to_tree(value, node, depth + 1)
            else:
                parent.add(f"[bold blue]{key} [/bold blue]: [bold]{value} [/bold]")  # Data (leaf nodes)

    tree = Tree("[bold]GPO Analysis [/bold]")
    analysed_to_tree(analysed, tree, depth=0)
    console = Console()
    console.print(tree)
