import logging
from rich.progress import track

class BloodHoundEnricher:
    """
    Enrich BloodHound data
    """

    def __init__(self, bloodhound_connector):
        self.bloodhound = bloodhound_connector

    def enrich(self, analyses, domain, domain_sid, ingestor):
        """
        Apply found vulnerabilies to containers trustees
        """

        output_enrichment = {"Memberships": {}, "Privilege Rights": {}, "Properties": {}}
        
        # Iterates over GPOs
        for data in track(analyses.values(), description=f"Enriching BloodHound with GPOs from {domain}", transient=True,):
            analysed_gpo = data["analysis"]
            container_ids = data["affected"]

            # Applies local group memberships to computers
            if "Memberships" in analysed_gpo:

                for analysed_settings in analysed_gpo["Memberships"].values():

                    for group in analysed_settings:

                        group_sid = group.get("sid")
                        group_name = group.get("name")
                        edge = group.get("edge")

                        if group_sid and edge:

                            if "Members" in group:

                                trustees_sid = []
                                for member in group["Members"]:
                                    sid = member.get("sid")
                                    if sid:
                                        trustees_sid.append(sid.upper())

                                # Try to add new relationship between the members of the groups and the machines in the containers
                                outputs = self.bloodhound.add_edges(domain_sid, container_ids, trustees_sid, edge)

                                if outputs:
                                    if ingestor == "bh-ce":
                                        try:
                                            self.bloodhound.add_edges_bhce(
                                                domain_sid, container_ids, trustees_sid, group_sid, group_name
                                            )
                                        except Exception as e:
                                            logging.debug("Error adding edges persistently for BloodHound CE: %s", e)

                                    if not isinstance(outputs, list):
                                        outputs = [outputs]

                                    for output in outputs:
                                        computer_name = output["c"]["samaccountname"]
                                        trustee_name = output["t"]["samaccountname"]
                                        output_enrichment["Memberships"].setdefault(group_name, {}).setdefault(
                                            trustee_name, set()
                                        ).add(computer_name)

                            if "EnvMembers" in group:
                                for entry in group["EnvMembers"]:
                                    if not entry["computer_name"] in output_enrichment["Memberships"].get(
                                        group_name, {}
                                    ).get(entry["name"], set()):
                                        output = self.bloodhound.add_edge(
                                            domain_sid, entry["sid"], entry["computer_sid"], edge
                                        )

                                        if output:
                                            if ingestor == "bh-ce":
                                                try:
                                                    self.bloodhound.add_edge_bhce(
                                                        domain_sid,
                                                        entry["sid"],
                                                        entry["computer_sid"],
                                                        group_sid,
                                                        group_name,
                                                    )
                                                except Exception as e:
                                                    logging.debug(
                                                        "Error adding edges persistently for BloodHound CE: %s", e
                                                    )

                                            computer_name = output["c"]["samaccountname"]
                                            trustee_name = output["t"]["samaccountname"]
                                            output_enrichment["Memberships"].setdefault(group_name, {}).setdefault(
                                                trustee_name, set()
                                            ).add(computer_name)

            # Adds interesting properties to computers
            if "Registry" in analysed_gpo:
                for analysed_settings in analysed_gpo["Registry"].values():

                    for registry in analysed_settings:
                        bloodhound_property = registry.get("bloodhound_property")

                        if bloodhound_property:

                            # Try to add new property to the machines in the containers
                            ((key, value),) = bloodhound_property.items()
                            outputs = self.bloodhound.add_extra_property(container_ids, key, value)

                            if outputs:
                                if not isinstance(outputs, list):
                                    outputs = [outputs]

                                for output in outputs:
                                    computer_name = output["n"]["samaccountname"]
                                    output_enrichment.setdefault("Properties", {}).setdefault((key, value), set()).add(
                                        computer_name
                                    )

            # Adds relationships to computers where trustees can escalate priviliges
            if "Privilege Rights" in analysed_gpo:
                for analysed_settings in analysed_gpo["Privilege Rights"].values():

                    for privilege, entry in analysed_settings.items():
                        edge = entry.get("edge")

                        trustees_sid = []
                        for trustee in entry["trustees"]:
                            sid = trustee.get("sid")
                            if sid:
                                trustees_sid.append(sid.upper())

                        if trustees_sid:

                            # Try to add new relationship between the privileged trustee and the machines in the container
                            outputs = self.bloodhound.add_edges(domain_sid, container_ids, trustees_sid, edge)

                            if not isinstance(outputs, list):
                                outputs = [outputs]

                            for output in outputs:
                                for output in outputs:
                                    computer_name = output["c"]["samaccountname"]
                                    trustee_name = output["t"]["samaccountname"]
                                    output_enrichment["Privilege Rights"].setdefault(privilege, {}).setdefault(
                                        trustee_name, set()
                                    ).add(computer_name)

        return output_enrichment
