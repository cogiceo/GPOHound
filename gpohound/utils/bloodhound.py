import logging
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError, CypherSyntaxError

logging.getLogger("neo4j").setLevel(logging.INFO)


class BloodHoundConnector:
    """
    Class to interact with BloodHound data
    """

    def __init__(self, host=None, user=None, password=None, port=None):
        self.uri = f"bolt://{host}:{port}"
        self.user = user
        self.password = password
        self.apoc = None

        try:
            # Create driver
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

            # Test connection
            self.connection = bool(self.query("RETURN 1"))

            # Check if APOC is available
            try:
                self.apoc = bool(self.query("RETURN apoc.version()"))
            except CypherSyntaxError as error:
                logging.debug("APOC plugin not available: %s", error)
                self.apoc = False

        except ServiceUnavailable as error:
            logging.debug("Unable to connect to Neo4j instance: %s", error)
            self.connection = False
            self.driver = None
        except AuthError as error:
            logging.debug("Could not authenticate to Neo4j database: %s", error)
            self.connection = False
            self.driver = None

    def query(self, query_str, params=None):
        """
        Execute query on the neo4j database
        """

        if params is None:
            params = {}

        with self.driver.session() as session:
            result = session.run(query_str, params)
            result_data = [record for record in result]

            if result_data:
                if len(result_data) == 1:
                    return result_data[0]
                else:
                    return result_data
        return None

    def close(self):
        if self.driver:
            self.driver.close()

    def find_domains(self):
        """
        Find all domains
        """
        query = """
                MATCH (n:Domain) 
                RETURN n
                """
        return self.query(query)

    def find_by_domain_name(self, domain):
        """
        Find domain by by domain name
        """
        params = {"domain": domain}
        query = """
                MATCH (n:Domain {domain:toUpper($domain)}) 
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    def find_by_gpo_guid(self, gpo_guid, domain_sid):
        """
        Find a GPO with his GUID and domain SID
        """
        params = {"gpo_guid": gpo_guid, "domain_sid": domain_sid}
        query = """
                MATCH (n:GPO) 
                WHERE toUpper(n.gpcpath) CONTAINS toUpper($gpo_guid) and toUpper(n.domainsid) = toUpper($domain_sid)
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    def find_by_samaccountname(self, samaccountname, domain_sid):
        """
        Find an object with a samaccountname
        """
        params = {"samaccountname": samaccountname, "domain_sid": domain_sid}
        query = """
                MATCH (n)
                WHERE ANY(label IN labels(n) WHERE label IN ['User', 'Group', 'Computer'])
                AND toUpper(n.samaccountname) = toUpper($samaccountname) and toUpper(n.domainsid) = toUpper($domain_sid)
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    def all_samaccountnames(self):
        """
        Return all the sAMAccountName
        """
        query = """
                MATCH (n)
                WHERE ANY(label IN labels(n) WHERE label IN ['User', 'Group', 'Computer'])
                AND n.samaccountname IS NOT NULL 
                RETURN n {.samaccountname, .objectid } AS n
                """

        return self.query(query)

    def find_by_objectid(self, objectid):
        """
        Find an object by his objectid
        """
        params = {"objectid": objectid}
        query = """
                MATCH (n)
                WHERE toUpper(n.objectid) = toUpper($objectid)
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    def find_container(self, target):
        """
        Find a container with a attribut of the container
        """
        params = {"target": target.upper()}
        query = """
                MATCH (n)
                WHERE ANY(label IN labels(n) WHERE label IN ['Container', 'Domain', 'OU'])
                AND (toUpper(n.distinguishedname) = $target OR toUpper(n.objectid) = $target) 
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    def find_trustee_container(self, target):
        """
        Find the container of a trustee
        """
        params = {"target": target.upper()}
        query = """
                MATCH (n)-[r1:Contains]->(t)
                WHERE ANY(label IN labels(t) WHERE label IN ['User', 'Computer'])
                AND ANY(label IN labels(n) WHERE label IN ['Container', 'Domain', 'OU'])
                AND (toUpper(t.distinguishedname) = $target OR toUpper(t.objectid) = $target OR toUpper(t.name) = $target)
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    # Disabled links fix in https://github.com/dirkjanm/BloodHound.py/pull/218
    def get_gpo_inheritance(self, objectid):
        """
        Get GPO application order for a container
        """
        params = {"objectid": objectid}
        query = """
                MATCH (o {objectid: $objectid}) 
                WITH o

                // Collect direct GPLinks first
                OPTIONAL MATCH (n:GPO)-[r1:GPLink]->(o) 
                WITH o, COLLECT({
                    node: n, 
                    enforced: r1.enforced, 
                    distance: 1, 
                    id: ID(n),
                    firstGPLinkId: ID(r1)  // Store the ID of the first GPLink relationship
                }) AS directLinks

                // Collect indirect GPLinks
                OPTIONAL MATCH p2 = (n:GPO)-[r2:GPLink]-(c)-[r3:Contains*1..]->(o) 
                WHERE ( 
                    (NONE(x IN TAIL(TAIL(NODES(p2))) WHERE x.blocksinheritance = true AND 'OU' IN LABELS(x))) 
                    OR r2.enforced = true
                    // TODO: Check this OR
                    OR ANY(label IN labels(o) WHERE label IN ['Container', 'Domain'])
                ) 
                WITH directLinks, COLLECT({
                    node: n, 
                    enforced: ANY(r2 IN RELATIONSHIPS(p2) WHERE type(r2) = "GPLink" AND r2.enforced = true), 
                    distance: LENGTH(p2), 
                    id: ID(n),
                    firstGPLinkId: ID(r2)
                }) AS indirectLinks

                WITH [g IN directLinks + indirectLinks WHERE g.node IS NOT NULL] AS allGPOs
                UNWIND allGPOs AS result

                // Sorting logic: 
                // Enforced relationships first (by enforced DESC), then by distance DESC, then GPLink ID DESC
                // Non-enforced relationships second, by distance ASC, then GPLink ID DESC
                WITH result
                ORDER BY 
                result.enforced DESC, 
                CASE WHEN result.enforced = true THEN result.distance END DESC,  // Enforced: distance DESC
                CASE WHEN result.enforced = false THEN result.distance END ASC,  // Non-enforced: distance ASC
                result.firstGPLinkId DESC  // GPLink ID DESC

                // Debug : RETURN result.node.name AS gpo_order, result.enforced AS enforced, result.firstGPLinkId AS first_gpLink_id, result.distance
                RETURN result.node AS n
                """

        return self.query(query, params)

    def containers_affected_by_gpo(self, gpo_guid, domain_sid):
        """
        Get not empty containers that are affected by a GPO
        """
        params = {"gpo_guid": gpo_guid, "domain_sid": domain_sid}
        query = """
                MATCH (g:GPO)
                WHERE toUpper(g.gpcpath) CONTAINS toUpper($gpo_guid) and toUpper(g.domainsid) = toUpper($domain_sid)
                WITH g

                // Collect direct GPLinks first
                OPTIONAL MATCH (g:GPO)-[r1:GPLink]->(c)-[r2:Contains]->(t)
                WHERE ANY(label IN labels(c) WHERE label IN ['Container','OU', 'Domain'])
                AND ANY(label IN labels(t) WHERE label IN ['User','Computer'])
                WITH g, COLLECT(DISTINCT c) as directContainer

                // Collect indirect GPLinks
                OPTIONAL MATCH p2 = (g:GPO)-[r3:GPLink]-()-[r4:Contains*1..]->(c)-[r5:Contains]->(t)
                WHERE ( 
                    ((NONE(x IN TAIL(TAIL(NODES(p2))) WHERE x.blocksinheritance = true AND 'OU' IN LABELS(x))) OR r3.enforced = true)
                    AND ANY(label IN labels(c) WHERE label IN ['Container','OU', 'Domain'])
                    AND ANY(label IN labels(t) WHERE label IN ['User','Computer'])
                ) 
                WITH directContainer, COLLECT(DISTINCT c) AS indirectContainer
                WITH directContainer + indirectContainer AS AllContainers
                UNWIND AllContainers AS n
                RETURN n
                """

        return self.query(query, params)

    def machines_affected_by_gpo(self, gpo_guid, domain_sid):
        """
        Get machines that are affected by a GPO
        """
        params = {"gpo_guid": gpo_guid, "domain_sid": domain_sid}
        query = """
                MATCH (g:GPO)
                WHERE toUpper(g.gpcpath) CONTAINS toUpper($gpo_guid) and toUpper(g.domainsid) = toUpper($domain_sid)
                WITH g

                // Collect machines from direct GPLink OU first
                OPTIONAL MATCH (g:GPO)-[r1:GPLink]->(c)-[r2:Contains]->(t:Computer)
                WHERE ANY(label IN labels(c) WHERE label IN ['Container','OU', 'Domain'])
                WITH g, t as directMachines

                // Collect machines from indirect GPLink OU
                OPTIONAL MATCH p2 = (g:GPO)-[r3:GPLink]-()-[r4:Contains*1..]->(c)-[r5:Contains]->(t:Computer)
                WHERE ((NONE(x IN TAIL(TAIL(NODES(p2))) WHERE x.blocksinheritance = true AND 'OU' IN LABELS(x))) OR r3.enforced = true)
                AND ANY(label IN labels(c) WHERE label IN ['Container','OU', 'Domain'])

                WITH directMachines, t AS indirectMachines
                WITH collect(directMachines) + collect(indirectMachines) AS AllMachines
                UNWIND AllMachines AS n
                RETURN DISTINCT n
                """

        return self.query(query, params)

    def machines_in_container(self, objectid, domain_sid):
        """
        Get machines that are affected by a GPO
        """
        params = {"objectid": objectid, "domain_sid": domain_sid}
        query = """
                MATCH (c)-[:Contains]->(n:Computer)
                WHERE ANY(label IN labels(c) WHERE label IN ['Container','OU', 'Domain'])
                AND toUpper(c.objectid) = toUpper($objectid) AND toUpper(c.domainsid) = toUpper($domain_sid)
                RETURN n
                """

        return self.query(query, params)

    def get_containers(self, domain_sid):
        """
        Get all containers of a domain
        """
        params = {"domain_sid": domain_sid}
        query = """
                MATCH (n) 
                WHERE n.domainsid = $domain_sid 
                AND ANY(label IN labels(n) WHERE label IN ['Container','OU', 'Domain'])
                RETURN DISTINCT n
                """

        return self.query(query, params)

    def get_not_empty_containers(self, domain_sid):
        """
        Get all not empty containers
        """
        params = {"domain_sid": domain_sid}
        query = """
                MATCH (n)-[r:Contains]->(l) 
                WHERE ANY(label IN labels(n) WHERE label IN ['Container','OU', 'Domain'])
                AND ANY(label IN labels(l) WHERE label IN ['Computer','User'])
                AND n.domainsid = $domain_sid 
                RETURN DISTINCT n
                """
        return self.query(query, params)

    def add_edge(self, domain_sid, trustee_sid, computer_objectid, edge):
        """
        Add a single edge between a trustee and a computer.
        """

        params = {
            "trustee_sid": trustee_sid,
            "domain_sid": domain_sid,
            "computer_objectid": computer_objectid,
            "edge": edge,
        }

        query = """
                MATCH (t)
                WHERE t.objectid IS NOT NULL
                AND toUpper(t.objectid) = $trustee_sid
                AND toUpper(t.domainsid) = $domain_sid
                MATCH (c:Computer {objectid: $computer_objectid})
                CALL apoc.merge.relationship(t, $edge, {gpohound:true}, {}, c) YIELD rel
                RETURN t, c
                """

        return self.query(query, params)

    def add_edges(self, domain_sid, container_ids, trustee_sids, edge):
        """
        Add relationship between a trustee and machines from a container
        """
        params = {
            "edge": edge,
            "container_ids": container_ids,
            "trustee_sids": trustee_sids,
            "domain_sid": domain_sid.upper(),
        }

        query = """
                // Collect all computers from all containers
                UNWIND $container_ids AS container_id
                MATCH (o {objectid: container_id})-[:Contains]->(c:Computer)
                WITH collect(DISTINCT c) AS computers

                // Match all trustees
                MATCH (t)
                WHERE t.objectid IS NOT NULL
                AND ANY(sid IN $trustee_sids WHERE toUpper(t.objectid) ENDS WITH sid)
                AND toUpper(t.domainsid) = $domain_sid
                
                // Merge relationships
                UNWIND computers AS c
                CALL apoc.merge.relationship(t, $edge, {gpohound: true}, {}, c) YIELD rel

                RETURN t, c
                """

        return self.query(query, params)

    def add_edge_bhce(self, domain_sid, trustee_sid, computer_objectid, group_sid, group_name):
        """
        Add a single trustee to a single computer's local group (BloodHound CE style).
        """
        trustee_sid = trustee_sid.upper()
        domain_sid = domain_sid.upper()
        group_name = group_name.upper()

        params = {
            "trustee_sid": trustee_sid,
            "domain_sid": domain_sid,
            "computer_objectid": computer_objectid,
            "group_rid": group_sid.split("-")[-1],
            "group_name": group_name,
        }

        query = """
                // Match the trustee
                MATCH (t)
                WHERE t.objectid IS NOT NULL
                AND toUpper(t.objectid) = $trustee_sid
                AND toUpper(t.domainsid) = $domain_sid

                // Match the computer
                MATCH (c:Computer {objectid: $computer_objectid})

                // Merge the local group
                MERGE (g:ADLocalGroup {objectid: toUpper(c.objectid + '-' + $group_rid)})
                ON CREATE SET g.name = $group_name + '@' + c.name

                // Merge relationships
                MERGE (t)-[:MemberOfLocalGroup]->(g)
                MERGE (g)-[:LocalToComputer]->(c)

                RETURN t, c
                """

        return self.query(query, params)

    def add_edges_bhce(self, domain_sid, container_ids, trustee_sids, group_sid, group_name):
        """
        Add relationships between a trustee, a local group and machines from a container for BloodHound CE.
        The naming follows SharpHound's convention: "GROUPNAME@COMPUTERNAME" in uppercase.
        Each computer has its own local groups, with "objectid" values in the format: COMPUTER_SID-GROUP_RID
        """

        params = {
            "container_ids": container_ids,
            "trustee_sids": trustee_sids,
            "domain_sid": domain_sid.upper(),
            "group_rid": group_sid.split("-")[-1],
            "group_name": group_name.upper(),
        }

        query = """
                // Expand all containers and collect computers
                UNWIND $container_ids AS container_id
                MATCH (o {objectid: container_id})-[:Contains]->(c:Computer)
                WITH collect(DISTINCT c) AS computers

                // Match all trustees
                MATCH (t)
                WHERE t.objectid IS NOT NULL
                AND toUpper(t.objectid) IN $trustee_sids
                AND toUpper(t.domainsid) = $domain_sid
                UNWIND computers AS c
                WITH t, c

                // Local group per computer
                WITH t, c, toUpper(c.objectid + '-' + $group_rid) AS local_group_id
                MERGE (g:ADLocalGroup {objectid: local_group_id})
                ON CREATE SET g.name = $group_name + '@' + c.name
                WITH t, g, c
                
                // Relationships
                CALL apoc.merge.relationship(t, 'MemberOfLocalGroup', {}, {}, g) YIELD rel AS rel1
                CALL apoc.merge.relationship(g, 'LocalToComputer', {}, {}, c) YIELD rel AS rel2

                RETURN t, c
                """
        return self.query(query, params)

    def add_extra_property(self, container_ids, property_key, property_value):
        """
        Add property to a machine in a container
        """

        params = {
            "container_ids": container_ids,
            "property_key": property_key,
            "property_value": property_value,
        }

        query = """
                UNWIND $container_ids AS container_id
                MATCH (o {objectid: container_id})-[:Contains]->(c:Computer)
                WITH c
                CALL apoc.create.setProperty(c, $property_key, $property_value)
                YIELD node AS n
                RETURN n
                """
        return self.query(query, params)
