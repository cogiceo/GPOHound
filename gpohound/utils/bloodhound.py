import logging
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError, CypherSyntaxError

logging.getLogger("neo4j").setLevel(logging.INFO)


class BloodHoundConnector:
    """
    Class to interact with BloodHound data
    """

    def __init__(self, host=None, user=None, password=None, port=None):
        self.uri = f"{host}:{port}"
        self.user = user
        self.password = password
        self.driver = None
        self.connection = bool(self.query("RETURN 1"))
        self.apoc = None

        if self.connection:
            try:
                self.apoc = bool(self.query("RETURN apoc.version()"))
            except CypherSyntaxError as error:
                logging.debug("Unable to use the APOC plugin : %s", error)

    def query(self, query_str, params=None):
        """
        Execute query on the neo4j database
        """

        if params is None:
            params = {}

        try:
            self.driver = GraphDatabase.driver(f"bolt://{self.uri}", auth=(self.user, self.password))

            with self.driver.session() as session:

                result = session.run(query_str, params)
                result_data = [record for record in result]

                if result_data:
                    if len(result_data) == 1:
                        return result_data[0]
                    else:
                        return result_data

            return None

        except ServiceUnavailable as error:
            logging.debug("Unable to connect to Neo4j instance : %s", error)
            return None
        except AuthError as error:
            logging.debug("Could not authenticate to Neo4j database: %s", error)
            return None

        finally:
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
        Find a GPO with his GUID and domain SID
        """
        params = {"samaccountname": samaccountname, "domain_sid": domain_sid}
        query = """
                MATCH (n) 
                WHERE toUpper(n.samaccountname) = toUpper($samaccountname) and toUpper(n.domainsid) = toUpper($domain_sid)
                RETURN n LIMIT 1
                """

        return self.query(query, params)

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
        params = {"target": target}
        query = """
                MATCH (n)
                WHERE (toUpper(n.distinguishedname) = toUpper($target) OR toUpper(n.objectid) = toUpper($target))
                AND ANY(label IN labels(n) WHERE label IN ['Container', 'Domain', 'OU'])
                RETURN n LIMIT 1
                """

        return self.query(query, params)

    def find_trustee_container(self, target):
        """
        Find the container of a trustee
        """
        params = {"target": target}
        query = """
                MATCH (n)-[r1:Contains]->(t)
                WHERE (toUpper(t.distinguishedname) = toUpper($target) OR toUpper(t.objectid) = toUpper($target) OR toUpper(t.name) = toUpper($target))
                AND ANY(label IN labels(t) WHERE label IN ['User', 'Computer'])
                AND ANY(label IN labels(n) WHERE label IN ['Container', 'Domain', 'OU'])
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
                MATCH (g)
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
                MATCH (g)
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
                WHERE n.domainsid = $domain_sid 
                AND ANY(label IN labels(n) WHERE label IN ['Container','OU', 'Domain'])
                AND ANY(label IN labels(l) WHERE label IN ['Computer','User'])
                RETURN DISTINCT n
                """
        return self.query(query, params)

    def add_edges(self, domain_sid, container_id, trustee_sid, edge):
        """
        Add relationship between a trustee and machines from a container
        """
        params = {
            "edge": edge,
            "container_id": container_id,
            "trustee_sid": trustee_sid,
            "domain_sid": domain_sid,
        }

        query = """
                MATCH (t) 
                WHERE toUpper(t.objectid) ENDS WITH toUpper($trustee_sid) AND toUpper(t.domainsid) = toUpper($domain_sid)
                WITH t
                MATCH (o {objectid: $container_id})-[r:Contains]->(c:Computer) 
                WITH t,c
                CALL apoc.merge.relationship(t, $edge, {gpohound:true} ,{}, c) YIELD rel WITH t,c
                RETURN t,c
                """
        return self.query(query, params)

    def add_edges_bhce(self, domain_sid, container_id, trustee_sid, group_sid, group_name):
        """
        Add relationships between a trustee, a local group and machines from a container for BloodHound CE

        The naming follows SharpHound's convention: "GROUPNAME@COMPUTERNAME" in uppercase.
        Each computer gets its own local groups with objectid format: COMPUTER_SID-GROUP_RID    
        """
        # Extract the RID from the group SID (e.g., "544" from "S-1-5-32-544") so we can create a new group below
        group_rid = group_sid.split('-')[-1]

        params = {
            "container_id": container_id,
            "trustee_sid": trustee_sid,
            "domain_sid": domain_sid,
            "group_rid": group_rid,
            "group_name": group_name.upper() if group_name else f"RID-{group_rid}",
        }

        query = """
                MATCH (t)
                WHERE toUpper(t.objectid) ENDS WITH toUpper($trustee_sid) AND toUpper(t.domainsid) = toUpper($domain_sid)
                WITH t
                MATCH (o {objectid: $container_id})-[r:Contains]->(c:Computer)
                WITH t, c, toUpper(c.objectid + '-' + $group_rid) AS local_group_id
                MERGE (g:Group {objectid: local_group_id})
                ON CREATE SET g.name = toUpper($group_name + '@' + c.name),
                              g.domainsid = toUpper($domain_sid)
                WITH t, c, g
                CALL apoc.merge.relationship(t, 'MemberOfLocalGroup', {}, {}, g) YIELD rel AS rel1
                WITH t, c, g
                CALL apoc.merge.relationship(g, 'LocalToComputer', {}, {}, c) YIELD rel AS rel2
                RETURN t, c, g
                """
        return self.query(query, params)

    def add_extra_property(self, container_id, property_key, property_value):
        """
        Add property to a machine in a container
        """

        params = {
            "container_id": container_id,
            "property_key": property_key,
            "property_value": property_value,
        }

        query = """
                MATCH (o {objectid: $container_id})-[r:Contains]->(c:Computer) 
                WITH c
                CALL apoc.create.setProperty(c, $property_key, $property_value) YIELD node as n
                RETURN n
                """
        return self.query(query, params)
