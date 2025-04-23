import re
import logging
from Crypto.Cipher import DES
from gpohound.utils.utils import load_yaml_config


class RegistryAnalyser:
    """Analyse registry keys content"""

    def __init__(self, config="config.analysis", config_file="registry.yaml"):
        self.registry_config = load_yaml_config(config, config_file)

    def analyse(self, processed_gpo):
        """
        Find interesting keys based on some conditions
        """

        results = {}

        for policy_type in ["User", "Machine"]:

            for config in ["Registry.xml", "registry.pol", "Registry Values"]:

                # Iterates over sensitive registry keys
                for sensitive_registry in self.registry_config:

                    for registry in processed_gpo.get(policy_type, {}).get(config, []):

                        # Try to match sensitive registry condition with current key
                        match sensitive_registry.get("condition"):

                            case "value_equals":
                                if (
                                    registry.get("Key").lower() == sensitive_registry.get("key").lower()
                                    and str(registry.get("Data").lower())
                                    == str(sensitive_registry.get("value")).lower()
                                ):
                                    entry = self.analysis_output(registry, sensitive_registry)
                                    results.setdefault(policy_type, []).append(entry)

                            case "value_less_than":
                                if registry.get("Key").lower() == sensitive_registry.get("key").lower() and int(
                                    registry.get("Data")
                                ) < int(sensitive_registry.get("value")):
                                    entry = self.analysis_output(registry, sensitive_registry)
                                    results.setdefault(policy_type, []).append(entry)

                            case "key_ends_with":
                                if registry.get("Key").lower().endswith(sensitive_registry.get("key").lower()):
                                    entry = self.analysis_output(registry, sensitive_registry)
                                    results.setdefault(policy_type, []).append(entry)

                            case "key_regex":
                                pattern = re.compile(sensitive_registry.get("key").lower())
                                if pattern.search(registry.get("Key").lower()):
                                    entry = self.analysis_output(registry, sensitive_registry)
                                    results.setdefault(policy_type, []).append(entry)

        return results

    def analysis_output(self, registry, sensitive_registry):
        """
        Return a dictionary for the analysed key and add property for bloodhound if specified
        """

        # Analysis output
        entry = {
            "analysis": sensitive_registry.get("analysis"),
            "regkey": f'{registry.get("Hive")}\\{registry.get("Key")}',
            "value": registry.get("Data"),
            "references": sensitive_registry.get("references"),
        }

        # If finding is a VNC password, try to decrypt it
        if sensitive_registry.get("decrypt") == "VNC" and entry.get("value"):
            decrypted_pass = self.decrypt_vnc_password(entry.get("value"))

            if decrypted_pass:
                entry.update({"VNC Password": decrypted_pass})
                entry.update({"bloodhound_property": {sensitive_registry.get("bloodhound_property"): decrypted_pass}})

        # Add a bloohound property if specified
        elif sensitive_registry.get("bloodhound_property"):
            entry.update({"bloodhound_property": sensitive_registry.get("bloodhound_property")})

        return entry

    def decrypt_vnc_password(self, cipher_hex):
        """
        Decrypt VNC password with public key
        """

        try:
            # Convert hex strings to bytes
            ciphertext = bytes.fromhex(cipher_hex)
            key = bytes.fromhex("e84ad660c4721ae0")
            iv = bytes.fromhex("0000000000000000")

            # Decrypt using DES CBC mode
            cipher = DES.new(key, DES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext).rstrip(b"\x00").decode("utf-8")

            # Return as string (decode assuming ASCII or fallback to latin1 for raw binary)
            return plaintext

        except ValueError as error:
            logging.debug("Error decrypting VNC password : %s", error)
            return None
