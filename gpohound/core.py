from pathlib import Path

from rich.console import Console

from gpohound.parser import GPOParser
from gpohound.processor import GPOProcessor
from gpohound.analyser import GPOAnalyser
from gpohound.enricher import BloodHoundEnricher

from gpohound.utils.bloodhound import BloodHoundConnector
from gpohound.utils.sqlite import SQLiteHandler
from gpohound.utils.ad import ActiveDirectoryUtils


console = Console(highlight=False)


class GPOHoundCore:
    """
    Class for parsing, processing and analysis of GPOs
    """

    def __init__(
        self,
        selected_policies,
        ldap_path=None,
        sysvol_path=None,
        neo4j_host=None,
        neo4j_user=None,
        neo4j_password=None,
        neo4j_port=None,
    ):

        self.sysvol_path = sysvol_path

        # BloodHound interactions
        self.bloodhound = BloodHoundConnector(neo4j_host, neo4j_user, neo4j_password, neo4j_port)
        self.bloodhound_enricher = BloodHoundEnricher(self.bloodhound)

        # LDAP SQLite interactions
        self.sqlite_handler = SQLiteHandler(ldap_path)

        # Active Directory utilities
        self.ad_utils = ActiveDirectoryUtils(self.bloodhound, self.sqlite_handler)

        # GPO parser, processor and analyser
        self.gpo_parser = GPOParser(selected_policies)
        self.gpo_processor = GPOProcessor(self.ad_utils)
        self.gpo_analyser = GPOAnalyser(self.ad_utils)

    def parse_file(self, file_path):
        """
        Parse a single policy file
        """

        file = Path(file_path)
        file_info = self.gpo_parser.file_info(file.parent, "", file.name)
        policy = self.gpo_parser.parse_file(file_info)

        return policy or None

    def get_ou_object(self, object, type="ou"):
        """
        Returns the OU of an object
        """

        if type == "ou":
            return self.ad_utils.find_ou(object)
        elif type == "trustee":
            return self.ad_utils.find_trustee_ou(object)
        else:
            return None

    def get_gpos_on_ou(self, ou):
        """
        Returns the GPOs applied to an OU
        """

        domain = self.ad_utils.find_by_sid(ou.get("domainsid"))
        if not domain:
            return None, None

        domain_name = domain.get("name", "").lower()

        ou_ordered_gpos = self.ad_utils.gpo_inheritance(ou.get("objectid"))
        if not ou_ordered_gpos:
            return None, None

        return domain_name, ou_ordered_gpos

    def resolve_gpo_name(self, domain_policies):
        """
        Resolves the GPO names
        """

        for domain, gpos in domain_policies.items():
            domain_sid = self.ad_utils.domain_to_sid(domain)
            if domain_sid:
                guids = list(gpos.keys())
                for guid in guids:
                    gpo = self.ad_utils.find_by_gpo_guid(guid, domain_sid)
                    if gpo:
                        # Move Name to the top of the dictionary
                        gpo_with_name = {"GPO Name": gpo.get("name")}
                        gpo_with_name.update(domain_policies[domain][guid])
                        domain_policies[domain][guid] = gpo_with_name

        return domain_policies

    def affected_ous(self, domain_policies):
        """
        Get OUs affected by the GPOs
        """

        for domain, gpos in domain_policies.items():
            domain_sid = self.ad_utils.domain_to_sid(domain)
            if domain_sid:
                guids = list(gpos.keys())
                for guid in guids:
                    ous = self.ad_utils.get_gpo_impact(guid, domain_sid)
                    if ous:
                        # Move Name to the top of the dictionary
                        gpo_with_ous = {"Affected OUs": ous}
                        gpo_with_ous.update(domain_policies[domain][guid])
                        domain_policies[domain][guid] = gpo_with_ous

        return domain_policies

    def parse_policies(self, domains=None, guids=None, affected=False):
        """
        Parse the GPOs in the SYSVOL
        """

        parsed_policies = self.gpo_parser.parse_domains_policies(self.sysvol_path, self.ad_utils, domains, guids)

        if not parsed_policies:
            return None

        if affected:
            parsed_policies = self.affected_ous(parsed_policies)

        parsed_policies = self.resolve_gpo_name(parsed_policies)

        return parsed_policies

    def list_policies(self, domains=None, guids=None):
        """
        List policies in the SYSVOL
        """

        parsed_policies = self.parse_policies(domains, guids)

        gpo_list = {}
        for domain, gpos in parsed_policies.items():
            tmp_list = []
            for guid, data in gpos.items():
                gpo_name = data.get("GPO Name")
                if gpo_name:
                    tmp_list.append(f"{guid}: {gpo_name}")
                else:
                    tmp_list.append(guid)
            gpo_list[domain] = tmp_list

        return gpo_list or None

    def dump_ou_gpos_settings(self, domain, ou_ordered_gpos, affected=False):
        """
        Get the GPOs settings on an OU
        """

        parsed_policies = self.parse_policies(domains=[domain], affected=affected)

        if not parsed_policies:
            return None

        gpo_inheritance = {}
        for idx, gpo in enumerate(ou_ordered_gpos, start=1):
            if "name" in gpo:
                gpo_guid = "{" + gpo["gpcpath"].split("{", 1)[1].split("}")[0] + "}"
                if gpo_guid in parsed_policies[domain]:
                    title = f"{idx} - {gpo_guid}"
                    data = parsed_policies[domain][gpo_guid]
                    if data:
                        gpo_inheritance[title] = data

        return gpo_inheritance or None

    def list_ou_gpos(self, ou_ordered_gpos):
        """
        Get a list of the GPOs on a list
        """

        gpo_list = []
        for idx, gpo in enumerate(ou_ordered_gpos, start=1):
            if "name" in gpo:
                gpo_guid = "{" + gpo["gpcpath"].split("{", 1)[1].split("}")[0] + "}"
                gpo_name = gpo["name"]
                gpo_list.append(f"{idx} - {gpo_guid}: {gpo_name}")
            else:
                gpo_list.append(f"{idx} - GPO not found in LDAP")

        return gpo_list or None

    def analyse_ou_gpos(self, domain, domain_sid, ou_ordered_gpos, objects=None, affected=False):
        """
        Get the analysis of GPOs on an OU
        """

        output = {}
        parsed_policies = self.parse_policies([domain], affected=affected)

        for gpo in ou_ordered_gpos:
            gpo_guid = "{" + gpo["gpcpath"].split("{", 1)[1].split("}")[0] + "}"

            if gpo_guid in parsed_policies[domain]:
                gpo_settings = parsed_policies[domain][gpo_guid]

                if gpo_settings:
                    processed_gpo = self.gpo_processor.process(gpo_settings, domain_sid, objects)
                    analysis = self.gpo_analyser.analyse(domain_sid, gpo_guid, gpo_settings, processed_gpo, objects)

                    if analysis:
                        gpo_output = output.setdefault(domain, {}).setdefault(gpo_guid, {})

                        if gpo_settings.get("GPO Name"):
                            gpo_output["GPO Name"] = gpo_settings.get("GPO Name")

                        if affected and (ous := self.ad_utils.get_gpo_impact(gpo_guid, domain_sid)):
                            gpo_output.setdefault("Affected OUs", {}).update(ous)

                        gpo_output.update(analysis)

        return output or None

    def analyse_all_gpos(self, domains=None, guids=None, objects=None, affected=False):
        """
        Get the analysis of GPOs in the SYSVOL
        """

        output = {}

        parsed_policies = self.parse_policies(affected=affected)

        if not parsed_policies:
            return None

        for domain, gpos in parsed_policies.items():

            domain_sid = self.ad_utils.domain_to_sid(domain)
            if domains and domain not in domains:
                continue

            # Iterates over GPOs
            for gpo_guid, gpo_settings in gpos.items():
                if guids and gpo_guid not in guids:
                    continue

                # Process the GPOs
                processed_gpo = self.gpo_processor.process(gpo_settings, domain_sid, objects)
                analysis = self.gpo_analyser.analyse(domain_sid, gpo_guid, gpo_settings, processed_gpo, objects)

                if analysis:
                    gpo_output = output.setdefault(domain, {}).setdefault(gpo_guid, {})

                    if gpo_settings.get("GPO Name"):
                        gpo_output["GPO Name"] = gpo_settings.get("GPO Name")

                    if affected and (ous := self.ad_utils.get_gpo_impact(gpo_guid, domain_sid)):
                        gpo_output.setdefault("Affected OUs", {}).update(ous)

                    gpo_output.update(analysis)

        return output or None

    def enrich_bloodhound(self, ingestor, domains=None, guids=None, objects=None):
        """
        Enrich BloodHound data
        """

        output_enrichment = {}
        parsed_policies = self.gpo_parser.parse_domains_policies(self.sysvol_path, self.ad_utils)

        if not parsed_policies:
            return None

        for domain, gpos in parsed_policies.items():

            enrichment_data = []

            domain_sid = self.ad_utils.domain_to_sid(domain)
            if domains and domain not in domains:
                continue

            # Iterates over GPOs
            for gpo_guid, gpo_settings in gpos.items():
                if guids and gpo_guid not in guids:
                    continue

                # Process the GPOs
                processed_gpo = self.gpo_processor.process(gpo_settings, domain_sid, objects)
                analysis = self.gpo_analyser.analyse(domain_sid, gpo_guid, gpo_settings, processed_gpo, objects)

                if analysis:
                    found_ous = self.ad_utils.get_ous_affected_by_gpo(gpo_guid, domain_sid)
                    if found_ous:
                        data = {
                            "analysis": analysis,
                            "affected": [ou.get("objectid") for ou in found_ous],
                        }
                        enrichment_data.append(data)

            if ingestor and domain_sid and enrichment_data:
                output = self.bloodhound_enricher.enrich(enrichment_data, domain, domain_sid, ingestor)
                if output:
                    output_enrichment[domain] = output

        return output_enrichment or None
