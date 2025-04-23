import os
import xml.etree.ElementTree as ET
from gpohound.utils.utils import load_yaml_config


class XMLParser:
    """XML files parser"""

    def __init__(self, config_folder="config.gpo_files_structure.xml") -> None:
        self.config = load_yaml_config(config_folder)

    def find_child_config(self, tag, config):
        """
        Recursively search all child configurations to find the first match for a given tag.
        This does NOT check the parent but looks through all child nodes in the config.
        """
        if not isinstance(config, dict) or "elements" not in config:
            return {}

        if tag in config["elements"]:
            return config["elements"][tag]

        # Search recursively in all child configs
        for value in config["elements"].values():
            if isinstance(value, dict):
                found_config = self.find_child_config(tag, value)
                if found_config:
                    return found_config

        return None  # Default to an empty config if nothing is found

    def parse_element(self, element, config):
        """
        Recursively parse an XML element based on the configuration.
        """

        if config and "include" not in config:
            return None

        data = {}

        # Extract attributes
        if config.get("attributes"):
            for attr in config["attributes"]:
                if attr in element.attrib:
                    data[attr] = element.attrib[attr]
        elif element.attrib:
            for attr in element.attrib:
                data[attr] = element.attrib[attr]
        if element.text and not element.text.replace("\n", "").isspace():
            data = element.text

        # Process child elements
        all_child_elements = element.findall("*")
        for child in all_child_elements:
            child_config = self.find_child_config(child.tag, config)
            if child_config:
                # Parse based on found config
                if "include" in child_config:
                    if len(element.findall(child.tag)) > 1:
                        if child.tag not in data:
                            data[child.tag] = []
                        data[child.tag].append(self.parse_element(child, child_config))
                    else:
                        data[child.tag] = self.parse_element(child, child_config)
            else:
                # If no config is found, get all the data from the unknown child element
                if len(element.findall(child.tag)) > 1:
                    if child.tag not in data:
                        data[child.tag] = []
                    data[child.tag].append(self.parse_element(child, {}))
                else:
                    data[child.tag] = self.parse_element(child, {})

        return data

    def parse(self, xml_file):
        """
        Parse the XML file based on the YAML configuration.
        """

        tree = ET.parse(xml_file)
        root = tree.getroot()

        if root.tag not in self.config:
            return None

        parsed_policy = self.parse_element(root, self.config[root.tag])

        if not parsed_policy:
            return None

        filename = os.path.basename(xml_file)
        policy_data = {filename: parsed_policy}

        return policy_data
