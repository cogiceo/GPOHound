import logging


class BloodHoundEnricher:
    """
    Enrich BloodHound data
    """

    def __init__(self, bloodhound_connector):
        self.bloodhound = bloodhound_connector

    def enrich(self, container_id, analysed_gpo, domain_sid):
        """
        Enrich BloodHound with the interesting settings found in a analaysed GPOs
        """
        results = {}

        if "Groups" in analysed_gpo:

            for policy_type, analysed_settings in analysed_gpo["Groups"].items():

                for group in analysed_settings:

                    group_sid = group.get("sid")
                    group_name = group.get("name")
                    edge = group.get("edge")

                    if group_sid and edge:
                        for member in group.get("Members", []):

                            member_sid = member.get("sid")
                            if member_sid:

                                # Try to add new relationship between the members of the groups and the machines in the container
                                outputs = self.bloodhound.add_edges(domain_sid, container_id, member_sid, edge)

                                if outputs:
                                    try:
                                        self.bloodhound.add_edges_bhce(
                                            domain_sid, container_id, member_sid, group_sid, group_name
                                        )
                                    except Exception as e:
                                        logging.debug("Error adding edges persistently for BloodHound CE: %s", e)

                                    if not isinstance(outputs, list):
                                        results.setdefault("Groups", {}).setdefault(policy_type, {}).setdefault(
                                            edge, []
                                        ).append(f'{outputs["t"]["name"]} -> {outputs["c"]["name"]}')
                                    else:
                                        for output in outputs:
                                            results.setdefault("Groups", {}).setdefault(policy_type, {}).setdefault(
                                                edge, []
                                            ).append(f'{output["t"]["name"]} -> {output["c"]["name"]}')

        if "Registry" in analysed_gpo:

            for policy_type, analysed_settings in analysed_gpo["Registry"].items():

                for registry in analysed_settings:
                    bloodhound_property = registry.get("bloodhound_property")

                    if bloodhound_property:

                        # Try to add new property to the machines in the container
                        ((key, value),) = bloodhound_property.items()
                        outputs = self.bloodhound.add_extra_property(container_id, key, value)

                        if outputs:
                            if not isinstance(outputs, list):
                                results.setdefault("Registry", {}).setdefault(policy_type, {}).setdefault(
                                    f"{key} is {value}", []
                                ).append(f'{outputs["n"]["name"]}')
                            else:
                                for output in outputs:
                                    results.setdefault("Registry", {}).setdefault(policy_type, {}).setdefault(
                                        f"{key} is {value}", []
                                    ).append(f'{output["n"]["name"]}')

        if "Privilege Rights" in analysed_gpo:

            for policy_type, analysed_settings in analysed_gpo["Privilege Rights"].items():

                for privilege in analysed_settings.values():
                    edge = privilege.get("edge")

                    for trustee in privilege.get("trustees", []):
                        trustee_sid = trustee.get("sid")

                        if trustee_sid:

                            # Try to add new relationship between the privileged trustee and the machines in the container
                            outputs = self.bloodhound.add_edges(domain_sid, container_id, trustee_sid, edge)

                            if outputs:
                                if not isinstance(outputs, list):
                                    results.setdefault("Privilege Rights", {}).setdefault(policy_type, {}).setdefault(
                                        edge, []
                                    ).append(f'{outputs["t"]["name"]} -> {outputs["c"]["name"]}')
                                else:
                                    for output in outputs:
                                        results.setdefault("Privilege Rights", {}).setdefault(
                                            policy_type, {}
                                        ).setdefault(edge, []).append(f'{output["t"]["name"]} -> {output["c"]["name"]}')

        return results
