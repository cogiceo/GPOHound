from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from gpohound.utils.utils import find_keys_recursive

from gpohound.analysers.groups import GroupAnalyser
from gpohound.analysers.registry import RegistryAnalyser
from gpohound.analysers.privilege_rights import PrivilegeRightsAnalyser


class GPOAnalyser:
    """Analyse GPOs"""

    def __init__(self, ad_utils):
        self.group_analyser = GroupAnalyser()
        self.registry_analyser = RegistryAnalyser()
        self.privilege_rights_analyser = PrivilegeRightsAnalyser(ad_utils)

    def analyse(self, gpo_settings, proccessed_gpo, objects):
        """
        Try to find interesting settings in GPO settings:
            - Sensitive group
            - Sensitive registry (network settings, password, etc...)
            - Sensitive priviliege allowing privilege escalation
            - Group Policy Preference Passwords
        """

        output = {}

        if proccessed_gpo:

            if not objects or "group" in objects:
                group_output = self.group_analyser.analyse(proccessed_gpo)
                if group_output:
                    output["Groups"] = group_output

            if not objects or "registry" in objects:
                registry_output = self.registry_analyser.analyse(proccessed_gpo)
                if registry_output:
                    output["Registry"] = registry_output

            if not objects or "privilege" in objects:
                privilege_rights_output = self.privilege_rights_analyser.analyse(proccessed_gpo)
                if privilege_rights_output:
                    output["Privilege Rights"] = privilege_rights_output

        if gpo_settings:
            if not objects or "gpppassword" in objects:
                cpasswords_output = self.find_gpp_password(gpo_settings)
                if cpasswords_output:
                    output["GPP Password"] = cpasswords_output

        return output

    def find_gpp_password(self, gpo_settings):
        """
        Find GPP Passwords in raw gpo settings
        """

        output = {}
        found_cpasswords = find_keys_recursive(gpo_settings, "cpassword")

        if found_cpasswords:
            for found_cpassword in found_cpasswords.get("cpassword", []):
                b64_password = found_cpassword.get("value")

                # Decrypt password if found
                if b64_password:
                    password = self.decrypt_gpppassword(b64_password)
                    output["\\".join(found_cpassword.get("path"))] = {
                        "encrypted": b64_password,
                        "decrypted": password,
                    }

        return output

    def decrypt_gpppassword(self, b64_password):
        """
        Decrypt GPP Password
        """

        # Decode base64 cpassword
        b64_password += "=" * ((4 - len(b64_password) % 4) % 4)
        cpassword = b64decode(b64_password)

        # Decryption key
        key = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")

        # Decrypt the password
        ctx = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        decrypted_password = unpad(ctx.decrypt(cpassword), ctx.block_size)

        return decrypted_password.decode("utf-16-le")
