import json
import copy
import sys
import logging

from gpohound.parser import GPOParser
from gpohound.processor import GPOProcessor
from gpohound.analyser import GPOAnalyser
from gpohound.enricher import BloodHoundEnricher

from gpohound.utils.utils import search_keys_values, print_dict_as_tree, print_processed, print_analysed, print_enriched
from gpohound.utils.bloodhound import BloodHoundConnector
from gpohound.utils.ad import ActiveDirectoryUtils

class GPOHoundCore:
    """
    Class for parsing, processing and analysis of GPOs
    """

    def __init__(
        self,
        policy_files,
        neo4j_host=None,
        neo4j_user=None,
        neo4j_password=None,
        neo4j_port=None,
    ):

        # BloodHound interactions
        self.bloodhound_connector = BloodHoundConnector(neo4j_host, neo4j_user, neo4j_password, neo4j_port)
        self.bloodhound_enricher = BloodHoundEnricher(self.bloodhound_connector)

        # Active Directory utilities
        self.ad_utils = ActiveDirectoryUtils(self.bloodhound_connector)

        # GPO parser, processor and analyser
        self.gpo_parser = GPOParser(policy_files)
        self.gpo_processor = GPOProcessor(self.ad_utils)
        self.gpo_analyser = GPOAnalyser(self.ad_utils)

    def dump(
        self,
        sysvol_path,
        domains=None,
        guids=None,
        gpo_name=None,
        print_json=None,
        list_gpos=None,
        search=None,
        show=None,
    ):
        """
        Dump GPO files and enrich data with bloodhound
        """

        if not self.ad_utils.bloodhound.connection and gpo_name:
            logging.info("This command requires a working bloodhound connection")
            sys.exit()

        self.gpo_parser.parse_domain_policies(sysvol_path)

        if not self.gpo_parser.policies:
            logging.info("No GPOs were found...")
            sys.exit()

        output = copy.deepcopy(self.gpo_parser.policies)

        # Only keep the specified domains
        if domains:
            tmp = {}

            for domain in domains:
                if domain in output:
                    tmp.update({domain: output[domain]})

            output = tmp

        # Only keep the specified GUIDs
        if guids:
            extracted = {}

            for domain, gpos in output.items():
                tmp = {}

                for guid in guids:
                    guid = "{" + guid.upper().strip("{").strip("}") + "}"

                    if guid in gpos:
                        tmp.setdefault(domain, {}).setdefault(guid, {}).update(gpos[guid])

                extracted.update(tmp)

            output = extracted

        # Searches in the output with a regex
        if search:
            output = search_keys_values(output, search, show)

        # Resolves GPO names
        if gpo_name and not search:
            output = self.ad_utils.resolve_gpo_name(output)

        # Only list the GPO GUIDs/names
        if list_gpos:
            tmp_dict = {}
            for domain, gpos in output.items():
                tmp_list = []
                for guid, data in gpos.items():
                    gpo_name = data.get("GPO Name")
                    if gpo_name:
                        tmp_list.append(f"{guid}: {gpo_name}")
                    else:
                        tmp_list.append(guid)
                tmp_dict[domain] = tmp_list
            output = tmp_dict

        # Print output
        if not output:
            logging.info("No GPOs were found for the given filter(s)...")
            sys.exit()

        if print_json:
            logging.info(json.dumps(output, indent=4))
        else:
            if search:
                print_dict_as_tree("Search results", output)
            else:
                print_dict_as_tree("GPOs", output)

    def analyser(
        self,
        sysvol_path,
        domains=None,
        guids=None,
        processed=False,
        affected=False,
        ingestor="",
        gpo_name=False,
        order=False,
        show=False,
        objects=None,
        container=None,
        computer=None,
        user=None,
        print_json=False,
    ):
        """
        Process the GPO and groups settings types
        Analysis of vulnerabilities in the GPOs settings
        Enrich bloodhooud with found vulnerabilites
        """

        if not self.ad_utils.bloodhound.connection and (
            affected or order or ingestor or container or user or computer or gpo_name or show
        ):
            logging.info("This command requires a working bloodhound connection")
            sys.exit()

        if not self.ad_utils.bloodhound.apoc and ingestor:
            logging.info(
                "This command requires to have APOC installed for Neo4j. Check the GPOHound documentation for more information"
            )
            sys.exit()

        if order and not (container or computer or user):
            logging.info("You need to specify a target...")
            sys.exit()

        self.gpo_parser.parse_domain_policies(sysvol_path)

        if not self.gpo_parser.policies:
            logging.info("No GPOs were found...")
            sys.exit()

        output_show = {}
        output_order = {}
        output_proccessed = {}
        output_analysis = {}
        output_enrichment = {}

        # Guids to parse
        if guids:
            guids = ["{" + guid.upper().strip("{").strip("}") + "}" for guid in guids]

        if container or computer or user:

            if container:
                found_container = self.ad_utils.find_container(container)
            elif computer:
                found_container = self.ad_utils.find_trustee_container(computer)
            else:
                found_container = self.ad_utils.find_trustee_container(user)

            if found_container:
                container_id = found_container.get("objectid")
                container_dn = found_container.get("distinguishedname")
                domain_sid = found_container.get("domainsid")
                domain = self.ad_utils.find_by_sid(domain_sid).get("name", "").lower()
                ordered_gpos = self.ad_utils.container_inheritance(container_id)

                if show:
                    gpo_inheritance = {}
                    for idx, gpo in enumerate(ordered_gpos, start=1):
                        if "name" in gpo:
                            gpo_guid = "{" + gpo["gpcpath"].split("{", 1)[1].split("}")[0] + "}"
                            if gpo_guid in self.gpo_parser.policies[domain]:
                                gpo_name = gpo["name"]
                                title = f"{idx} - {gpo_guid}: {gpo_name}"
                                data = self.gpo_parser.policies[domain][gpo_guid]
                                if data:
                                    if container:
                                        gpo_inheritance[title] = data
                                    elif computer and data.get("Machine"):
                                        gpo_inheritance[title] = data.get("Machine")
                                    elif user and data.get("User"):
                                        gpo_inheritance[title] = data.get("User")
                            else:
                                title = f"{idx} - Empty GPO"
                                gpo_inheritance[title] = None
                        else:
                            title = f"{idx} - Unknown GPO"
                            gpo_inheritance[title] = None
                    output_show.update({container_dn: gpo_inheritance})

                elif order:
                    gpo_inheritance = []
                    for idx, gpo in enumerate(ordered_gpos, start=1):
                        if "name" in gpo:
                            gpo_guid = "{" + gpo["gpcpath"].split("{", 1)[1].split("}")[0] + "}"
                            gpo_name = gpo["name"]
                            gpo_inheritance.append(f"{idx} - {gpo_guid}: {gpo_name}")
                        else:
                            gpo_inheritance.append(f"{idx} - Unknown GPO")
                    output_order.update({container_dn: gpo_inheritance})

                elif domain and domain_sid and domain in self.gpo_parser.policies:
                    gpo_settings = {}
                    for gpo in ordered_gpos:
                        if "name" in gpo:
                            gpo_guid = "{" + gpo["gpcpath"].split("{", 1)[1].split("}")[0] + "}"
                            if gpo_guid in self.gpo_parser.policies[domain]:
                                gpo_name = gpo["name"]
                                gpo_settings = self.gpo_parser.policies[domain][gpo_guid]
                                if gpo_settings:

                                    proccessed_gpo = self.gpo_processor.process(gpo_settings, objects, domain_sid)

                                    if proccessed_gpo and processed:
                                        output_proccessed.setdefault(domain, {}).setdefault(gpo_guid, {}).update(
                                            proccessed_gpo
                                        )

                                    elif proccessed_gpo:
                                        analysis = self.gpo_analyser.analyse(
                                            domain_sid, gpo_guid, gpo_settings, proccessed_gpo, objects
                                        )

                                        if analysis:
                                            output_analysis.setdefault(domain, {}).setdefault(gpo_guid, {}).update(
                                                analysis
                                            )

        else:
            # Iterates over domains
            for domain, gpos in self.gpo_parser.policies.items():

                analyses = {}

                domain_sid = self.ad_utils.domain_to_sid(domain)
                if domains and domain not in domains:
                    continue

                # Iterates over GPOs
                for gpo_guid, gpo_settings in gpos.items():
                    if guids and gpo_guid not in guids:
                        continue

                    # Process the GPOs
                    proccessed_gpo = self.gpo_processor.process(gpo_settings, objects, domain_sid)

                    # Proccessed settings output
                    if proccessed_gpo and processed:
                        output_proccessed.setdefault(domain, {}).setdefault(gpo_guid, {}).update(proccessed_gpo)

                    # Analyse the GPOs settings
                    else:
                        analysis = self.gpo_analyser.analyse(
                            domain_sid, gpo_guid, gpo_settings, proccessed_gpo, objects
                        )

                        if analysis:

                            # Get container list affected by the GPO
                            if (affected or ingestor) and domain_sid:
                                found_containers = self.ad_utils.get_containers_affected_by_gpo(gpo_guid, domain_sid)

                                if found_containers:    
                                    # Get analysis data and affected containers for enrichement
                                    if ingestor:
                                        analyses[gpo_guid] = {
                                            "analysis": analysis,
                                            "affected": [container.get("objectid") for container in found_containers],
                                        }

                                    # Add container list to processed GPO and vulnerability outputs
                                    if affected:
                                        containers_dn = [
                                            container.get("distinguishedname") for container in found_containers
                                        ]
                                        output_analysis.setdefault(domain, {}).setdefault(gpo_guid, {}).setdefault(
                                            "Affected Containers", []
                                        ).extend(containers_dn)
                                        output_analysis.setdefault(domain, {}).setdefault(gpo_guid, {}).update(analysis)

                            else:
                                # Analysis output to print
                                output_analysis.setdefault(domain, {}).setdefault(gpo_guid, {}).update(analysis)

                # Enrich bloodhound with found vulnerabilities
                if ingestor and domain_sid and analyses:
                    output_enrichment[domain] = self.bloodhound_enricher.enrich(analyses, domain, domain_sid, ingestor)

        # Print processed settings
        if processed:
            if not output_proccessed:
                logging.info("No processed GPO settings were found...")
                sys.exit()
            if gpo_name:
                output_proccessed = self.ad_utils.resolve_gpo_name(output_proccessed)
            if print_json:

                print(json.dumps(output_proccessed, indent=4))
            else:
                print_processed(output_proccessed)

        # Print enrichement output
        elif ingestor:
            if not output_enrichment:
                logging.info("No GPOs found to enrich BloodHound data...")
                sys.exit()

            if print_json:
                print(json.dumps(output_enrichment, indent=4))
            else:
                print_enriched(output_enrichment)

        # Print GPO settings in order
        elif show:
            if output_show:
                if print_json:
                    print(json.dumps(output_show, indent=4))
                else:
                    print_dict_as_tree("Applied GPO in order ", output_show)

        # Print GPO order output
        elif order:
            if not output_order:
                logging.info("No order for this target...")
                sys.exit()
            if print_json:
                print(json.dumps(output_order, indent=4))
            else:
                print_dict_as_tree("GPO Order ", output_order)

        # Print analysis output
        elif output_analysis:
            if gpo_name:
                output_analysis = self.ad_utils.resolve_gpo_name(output_analysis)
            if print_json:
                print(json.dumps(output_analysis, indent=4))
            else:
                print_analysed(output_analysis)

        else:
            logging.info("No results were found for the specified settings...")
            sys.exit()
