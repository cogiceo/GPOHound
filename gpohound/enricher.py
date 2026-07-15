import logging
from rich.progress import track


class BloodHoundEnricher:
    """
    Enrich BloodHound data
    """

    def __init__(self, bloodhound):
        self.bloodhound = bloodhound

    def enrich(self, analyses, domain, domain_sid, ingestor):
        """
        Apply found vulnerabilies to ous trustees
        """

        output_enrichment = {"Memberships": {}, "Privilege Rights": {}, "Properties": {}}

        # Iterates over GPOs
        for data in track(
            analyses,
            description=f"Enriching BloodHound with GPOs from {domain}",
            transient=True,
        ):
            analysed_gpo = data["analysis"]
            ou_ids = data["affected"]

            # Applies local group memberships to computers
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

                                # Try to add new relationship between the members of the groups and the machines in the ous
                                outputs = self.bloodhound.add_edges(domain_sid, ou_ids, trustees_sid, edge)

                                if outputs:
                                    if ingestor == "bh-ce":
                                        try:
                                            self.bloodhound.add_edges_bhce(
                                                domain_sid, ou_ids, trustees_sid, group_sid, group_name
                                            )
                                        except Exception as e:
                                            logging.debug(f"Error adding edges persistently for BloodHound CE: {e}")

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
                                                        f"Error adding edges persistently for BloodHound CE: {e}"
                                                    )

                                            computer_name = output["c"]["samaccountname"]
                                            trustee_name = output["t"]["samaccountname"]
                                            output_enrichment["Memberships"].setdefault(group_name, {}).setdefault(
                                                trustee_name, set()
                                            ).add(computer_name)

            # Adds interesting properties to computers
            if "Registry" in analysed_gpo:
                for analysed_settings in analysed_gpo["Registry"].values():

                    for registry in analysed_settings:
                        bloodhound_property = registry.get("bloodhound_property")

                        if bloodhound_property:

                            # Try to add new property to the machines in the ous
                            ((key, value),) = bloodhound_property.items()
                            outputs = self.bloodhound.add_extra_property(ou_ids, key, value)

                            if outputs:
                                for output in outputs:
                                    computer_name = output["n"]["samaccountname"]
                                    output_enrichment.setdefault("Properties", {}).setdefault((key, value), set()).add(
                                        computer_name
                                    )

            # Adds relationships to computers where trustees can escalate priviliges
            if "Privilege Rights" in analysed_gpo:
                for analysed_settings in analysed_gpo["Privilege Rights"].values():

                    for privilege, entry in analysed_settings.items():
                        edge = entry.get("edge")

                        if not edge:
                            continue

                        trustees_sid = []
                        for trustee in entry["trustees"]:
                            sid = trustee.get("sid")
                            if sid:
                                trustees_sid.append(sid.upper())

                        if trustees_sid:

                            # Try to add new relationship between the privileged trustee and the machines in the ou
                            outputs = self.bloodhound.add_edges(domain_sid, ou_ids, trustees_sid, edge)

                            if outputs:
                                for output in outputs:
                                    computer_name = output["c"]["samaccountname"]
                                    trustee_name = output["t"]["samaccountname"]
                                    output_enrichment["Privilege Rights"].setdefault(privilege, {}).setdefault(
                                        trustee_name, set()
                                    ).add(computer_name)

        if all(not value for value in output_enrichment.values()):
            return None

        return output_enrichment
