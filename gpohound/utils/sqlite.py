import re
import json
import sqlite3

from pathlib import Path
from datetime import datetime


class SQLiteHandler:
    """
    Multi-database SQLite handler
    """

    def __init__(self, dbs_path):

        self.dbs = {}

        if dbs_path:
            for db_file in Path(dbs_path).glob("*.sqlite"):
                conn = sqlite3.connect(db_file)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT * FROM domain LIMIT 1")
                rows = cur.fetchall()
                cur.close()
                if rows:
                    result = [dict(r) for r in rows]
                    if result:
                        self.dbs[result[0]["objectSid"]] = conn

    def to_dict_bh(self, row, domainsid, obj_type=""):
        """
        Convert objects to BloodHound-formatted dictionaries
        """

        dict_row = dict(row)
        dict_row["distinguishedname"] = dict_row["distinguishedName"].upper()
        dict_row["domainsid"] = domainsid
        match obj_type:
            case "domain":
                dn = dict_row["distinguishedname"]
                dict_row["objectid"] = dict_row["objectSid"]
                dict_row["name"] = re.sub(",DC=", ".", dn[dn.find("DC=") :], flags=re.I)[3:]
            case "gpo":
                dict_row["objectid"] = dict_row["objectGUID"].upper()
                dict_row["name"] = dict_row["displayName"].upper()
                dict_row["gpcpath"] = dict_row["gPCFileSysPath"].upper()
            case "trustee":
                dict_row["objectid"] = dict_row["objectSid"]
                dict_row["name"] = dict_row["sAMAccountName"]
                dict_row["samaccountname"] = dict_row["sAMAccountName"]

            case "ou":
                dict_row["objectid"] = dict_row["objectGUID"].upper()
                dict_row["blocksinheritance"] = True if dict_row.get("gPOptions") else False

        return dict_row

    def query_db(self, domain_sid, sql, params=(), obj_type=""):
        """
        Query a single database
        """
        db = self.dbs.get(domain_sid)
        if not db:
            return None

        cur = db.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
        if rows:
            return [self.to_dict_bh(r, domain_sid, obj_type) for r in rows]
        return None

    def query_all(self, sql, params=(), obj_type=""):
        """
        Query all databases and return a single merged list
        """
        results = []

        for domain_sid, db in self.dbs.items():
            cur = db.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            cur.close()
            if rows:
                results.extend([self.to_dict_bh(r, domain_sid, obj_type) for r in rows])

        return results

    def first_match(self, sql, params=(), obj_type=""):
        """
        First match on all databases
        """
        for domain_sid, db in self.dbs.items():
            cur = db.cursor()
            cur.execute(sql, params)
            row = cur.fetchone()
            cur.close()
            if row:
                return self.to_dict_bh(row, domain_sid, obj_type)

        return None

    def find_domains(self):
        query = "SELECT * FROM domain LIMIT 1"
        params = ()
        return self.query_all(query, params, obj_type="domain")

    def find_by_domain_name(self, domain):
        domain_dn = ",".join(f"DC={part}" for part in domain.split("."))

        query = "SELECT * FROM domain WHERE UPPER(distinguishedName) = UPPER(?)"
        params = (domain_dn,)

        return self.first_match(query, params, obj_type="domain")

    def get_ous(self, domain_sid):
        query = "SELECT * FROM ous"
        params = ()

        return self.query_db(domain_sid, query, params, obj_type="ou")

    def find_ou(self, target):
        query = "SELECT *FROM ous WHERE UPPER(distinguishedName) = UPPER(?) OR UPPER(objectGUID) = UPPER(?)"
        params = (target, target)

        return self.first_match(query, params, obj_type="ou")

    def find_by_gpo_guid(self, gpo_guid, domain_sid):
        query = "SELECT * FROM gpos WHERE UPPER(gPCFileSysPath) LIKE '%' || UPPER(?) || '%'"
        params = (gpo_guid,)
        result = self.query_db(domain_sid, query, params, obj_type="gpo")

        if result:
            return result[0]
        return None

    def find_by_samaccountname(self, samaccountname, domain_sid):
        query = "SELECT * FROM trustees WHERE UPPER(sAMAccountName) = UPPER(?)"
        params = (samaccountname,)
        result = self.query_db(domain_sid, query, params, obj_type="trustee")

        if result:
            return result[0]
        return None

    def all_samaccountnames(self):
        query = "SELECT * FROM trustees WHERE sAMAccountName IS NOT NULL"
        params = ()

        return self.query_all(query, params, obj_type="trustee")

    def find_by_objectid(self, objectid):
        query = "SELECT * FROM domain WHERE UPPER(objectSid) = UPPER(?)"
        params = (objectid,)

        result = self.first_match(query, params, obj_type="domain")
        if result:
            return result

        query = "SELECT * FROM trustees WHERE UPPER(objectSid) = UPPER(?)"
        params = (objectid,)

        result = self.first_match(query, params, obj_type="trustee")
        if result:
            return result

        query = "SELECT * FROM gpos WHERE UPPER(objectGUID) = UPPER(?)"
        params = (objectid,)

        result = self.first_match(query, params, obj_type="gpo")
        if result:
            return result

        return None

    def find_trustee_ou(self, target):
        """
        Resolve trustee OU using domain SID
        """

        domain = None
        domain_sid = None
        sam = None

        # Parse bloodhound names input formats
        if "@" in target:
            # Users
            sam, domain_part = target.split("@", 1)
            domain = self.find_by_domain_name(domain_part)

        elif "." in target and "\\" not in target:
            # Computers
            sam = target.split(".")[0] + "$"
            domain_part = ".".join(target.split(".")[1:])
            domain = self.find_by_domain_name(domain_part)

        if domain:
            domain_sid = domain.get("objectSid")

        if not domain_sid in self.dbs.keys():
            query = """
            SELECT
                o.*,
                t.distinguishedName AS trustee_dn
            FROM trustees t
            JOIN ous o
                ON UPPER(o.distinguishedName) = UPPER(
                    substr(
                        t.distinguishedName,
                        instr(t.distinguishedName, ',') + 1
                    )
                )
            WHERE UPPER(t.distinguishedName) = UPPER(?)
            OR UPPER(t.objectSid) = UPPER(?)
            LIMIT 1
            """
            params = (
                target,
                target,
            )

            row = self.first_match(query, params, obj_type="ou")

            if row:
                return row

        else:
            query = """
            SELECT
                o.*,
                t.distinguishedName AS trustee_dn
            FROM trustees t
            JOIN ous o
                ON UPPER(o.distinguishedName) = UPPER(
                    substr(
                        t.distinguishedName,
                        instr(t.distinguishedName, ',') + 1
                    )
                )
            WHERE UPPER(t.samaccountname) = UPPER(?)
            LIMIT 1
            """
            params = (sam,)

            row = self.query_db(domain_sid, query, params, obj_type="ou")
            if row:
                return row[0]

        return None

    def parse_wmi_filter(self, value):
        """
        Parse gPCWQLFilter value.
        """

        if not value:
            return None

        match = re.match(r"\[(.*?);(\{[0-9A-Fa-f-]+\});(\d+)\]", value)

        if not match:
            return None

        return {
            "domain": match.group(1),
            "guid": match.group(2),
            "flags": match.group(3),
        }

    def parse_wmi_time(self, value):
        if not value:
            return None

        # remove timezone suffix like -000 or +000
        base = value.split(".")[0]  # "20260524165602"
        micro = value.split(".")[1][:6] if "." in value else "0"

        dt = datetime.strptime(base, "%Y%m%d%H%M%S")
        dt = dt.replace(microsecond=int(micro))

        return str(dt)

    def parse_wmi_commands(self, value):
        """
        Parse msWMI-Parm2.
        """

        if not value:
            return []

        parts = value.split(";")
        commands = []

        i = 0

        while i < len(parts):
            if i + 5 >= len(parts):
                break

            language = parts[i + 4].strip()
            namespace = parts[i + 5].strip()
            query = parts[i + 6].strip()

            if language and namespace and query:
                commands.append(
                    {
                        "Language": language,
                        "Namespace": namespace,
                        "Query": query,
                    }
                )

            # Move to next block
            i += 6

        return commands

    def get_wmi_filter(self, gpo_guid, domain_sid):
        """
        Resolve WMI filter associated to a GPO.
        """

        query = "SELECT * FROM gpos WHERE UPPER(gPCFileSysPath) LIKE '%' || UPPER(?) || '%'"
        params = (gpo_guid,)

        gpo = self.query_db(domain_sid, query, params, obj_type="gpo")
        if not gpo:
            return None

        gpc_wql_filter = gpo[0].get("gPCWQLFilter")

        parsed = self.parse_wmi_filter(gpc_wql_filter)
        if not parsed:
            return None

        guid = parsed["guid"].upper()

        query = "SELECT * FROM wmi_filters WHERE UPPER(msWMI_ID) = ? LIMIT 1"
        params = (guid,)

        wmi_filter = self.query_db(domain_sid, query, params)

        if not wmi_filter:
            return None

        return {
            "Name": wmi_filter[0].get("msWMI_Name"),
            "Description": wmi_filter[0].get("msWMI_Parm1"),
            "Author": wmi_filter[0].get("msWMI_Author"),
            # "ID": wmi_filter[0].get("msWMI_ID"),
            # "ChangeDate": self.parse_wmi_time(wmi_filter[0].get("msWMI_ChangeDate")),
            # "CreationDate": self.parse_wmi_time(wmi_filter[0].get("msWMI_CreationDate")),
            "Command": self.parse_wmi_commands(wmi_filter[0].get("msWMI_Parm2")),
        }

    def get_deployed_printers(self, domain_sid):
        """
        Get all deployed printers.
        """

        query = "SELECT * FROM printers"
        params = ()

        return self.query_db(domain_sid, query, params)

    def parse_gplink(self, gplink):
        """
        Parse gPLink and directly separate enforced/normal GPOs while preserving correct application order.
        """

        if not gplink:
            return {"enforced": [], "normal": []}

        enforced = []
        normal = []

        links = []

        for chunk in gplink.split("]["):
            m = re.search(r"\{[0-9A-Fa-f-]+\}", chunk)
            if not m:
                continue

            cn = m.group(0)

            flag_match = re.search(r";(\d)", chunk)
            flag = int(flag_match.group(1)) if flag_match else 0

            # ignore disabled links
            if flag in (1, 3):
                continue

            links.append((cn, flag))

        for cn, flag in links:
            if flag == 2:
                enforced.append(cn)
            else:
                normal.append(cn)

        normal.reverse()
        return {"enforced": enforced, "normal": normal}

    def build_gpo_inheritance(self, ous):
        """
        Build GPO inheritance order.
        """

        enforced_gpos = []
        normal_gpos = []

        blocked = False

        for ou in sorted(ous, key=lambda x: x.get("depth", 0)):
            parsed = self.parse_gplink(ou.get("gPLink"))

            # normal GPOs
            for cn in parsed["normal"]:
                if blocked:
                    continue

                normal_gpos.append(cn)

            # enforced GPOs always survive blocking
            enforced_gpos.extend(parsed["enforced"])

            # current OU blocks inheritance
            if ou.get("blocksinheritance"):
                blocked = True

        enforced_gpos.reverse()

        # enforced GPOs apply last
        return enforced_gpos + normal_gpos

    def get_gpo_inheritance(self, ou_id):

        # Get parents of an OU
        query = """
        WITH RECURSIVE ou_tree AS (
            SELECT
                id,
                distinguishedName,
                objectGUID,
                name,
                gPLink,
                gPOptions,
                0 AS depth
            FROM ous
            WHERE UPPER(objectGUID) = UPPER(?)

            UNION ALL

            SELECT
                parent.id,
                parent.distinguishedName,
                parent.objectGUID,
                parent.name,
                parent.gPLink,
                parent.gPOptions,
                child.depth + 1
            FROM ous parent
            JOIN ou_tree child
                ON parent.distinguishedName =
                    (
                        SELECT
                            CASE
                                WHEN instr(child.distinguishedName, ',') > 0
                                THEN substr(child.distinguishedName, instr(child.distinguishedName, ',') + 1)
                                ELSE NULL
                            END
                    )
            WHERE parent.distinguishedName IS NOT NULL
        )

        SELECT DISTINCT *
        FROM ou_tree;
        """
        params = (ou_id,)

        output = self.query_all(query, params, obj_type="ou")

        if not output:
            return
        domain_sid = output[0].get("domainsid", "")

        gpo_cns = self.build_gpo_inheritance(output)
        if not gpo_cns:
            return

        query = """
        SELECT g.*
        FROM gpos g
        JOIN json_each(?) j
            ON UPPER(g.cn) = UPPER(j.value)
        ORDER BY CAST(j.key AS INTEGER)
        """
        params = (json.dumps(gpo_cns),)

        output = self.query_db(domain_sid, query, params, "gpo")
        return output

    def walk_child_ous(self, domain_sid, distinguished_name, enforced=False):
        """
        Recursively retrieve an OU and its descendants, honoring GPO inheritance
        """

        query = """
        WITH RECURSIVE ou_tree AS (

            SELECT
                id,
                distinguishedName,
                objectGUID,
                gPLink,
                gPOptions
            FROM ous
            WHERE UPPER(distinguishedName) = UPPER(?)

            UNION ALL

            SELECT
                o.id,
                o.distinguishedName,
                o.objectGUID,
                o.gPLink,
                o.gPOptions
            FROM ous o
            JOIN ou_tree parent
                ON UPPER(
                    substr(
                        o.distinguishedName,
                        instr(o.distinguishedName, ',') + 1
                    )
                ) = UPPER(parent.distinguishedName)

            WHERE
                ? = 1
                OR o.gPOptions = '0'
        )

        SELECT DISTINCT *
        FROM ou_tree
        """

        params = (
            distinguished_name,
            1 if enforced else 0,
        )

        return self.query_db(domain_sid, query, params, obj_type="ou")

    def ous_affected_by_gpo(self, gpo_guid, domain_sid):

        # Get the GPO informations
        query = "SELECT * FROM gpos WHERE UPPER(gPCFileSysPath) LIKE '%' || UPPER(?) || '%' LIMIT 1"
        params = (gpo_guid,)

        gpo = self.query_db(domain_sid, query, params, obj_type="gpo")

        if not gpo:
            return []

        gpo_cn = gpo[0].get("cn")

        # Get all the OUs that have a gPLink
        query = "SELECT * FROM ous WHERE UPPER(gPLink) LIKE '%' || UPPER(?) || '%'"
        params = (gpo_cn,)

        ous = self.query_db(domain_sid, query, params, obj_type="ou")
        if not ous:
            return []

        affected = {}

        for ou in ous:

            # Parsing of each gPlink of every OU
            parsed = self.parse_gplink(ou.get("gPLink"))

            enforced = False
            if gpo_cn in parsed["enforced"]:
                enforced = True

            # Get affected child OUs
            results = self.walk_child_ous(
                domain_sid,
                ou.get("distinguishedName"),
                enforced=enforced,
            )

            for result in results:
                ou_dn = result["distinguishedName"].upper()
                if not ou_dn in affected:
                    affected[result["distinguishedName"].upper()] = self.to_dict_bh(result, domain_sid, "ou")

        return list(affected.values())

    def get_obj_in_ou(self, ou_id, domain_sid, obj_type=None):
        query = """
        WITH parent AS (
            SELECT distinguishedName
            FROM ous
            WHERE UPPER(objectGUID) = UPPER(?)
        )
        
        SELECT t.*
        FROM trustees t, parent p
        WHERE (
            UPPER(t.distinguishedName) LIKE '%,' || UPPER(p.distinguishedName)
            AND (
                LENGTH(t.distinguishedName) - LENGTH(REPLACE(t.distinguishedName, ',', ''))
                =
                LENGTH(p.distinguishedName) - LENGTH(REPLACE(p.distinguishedName, ',', '')) + 1
            )
        )
        AND (
            ? IS NULL
            OR UPPER(t.type) = UPPER(?)
        );
        """

        params = (ou_id, obj_type, obj_type)

        return self.query_db(domain_sid, query, params, obj_type="trustee")


class LDAPDatabaseBuilder:
    """
    Class to create and populate the database
    """

    def __init__(self, db_path, overwrite=False):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if overwrite and self.db_path.exists():
            self.db_path.unlink()

        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def init_db(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS domain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                distinguishedName TEXT,
                objectSid TEXT
            )
        """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS gpos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                distinguishedName TEXT,
                objectGUID TEXT,
                cn TEXT,
                displayName TEXT,
                versionNumber TEXT,
                gPCFileSysPath TEXT,
                gPCMachineExtensionNames TEXT,
                gPCUserExtensionNames TEXT,
                gPCFunctionalityVersion TEXT,
                flags TEXT,
                gPCWQLFilter TEXT,
                nTSecurityDescriptor TEXT
            )
        """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS trustees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                distinguishedName TEXT,
                objectSid TEXT,
                sAMAccountName TEXT,
                type TEXT
            )
        """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ous (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                distinguishedName TEXT,
                objectGUID TEXT,
                name TEXT,
                gPLink TEXT,
                gPOptions INT
            )
        """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS wmi_filters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                distinguishedName TEXT,
                msWMI_ID TEXT,
                msWMI_Name TEXT,
                msWMI_Parm1 TEXT,
                msWMI_Author TEXT,
                msWMI_ChangeDate TEXT,
                msWMI_CreationDate TEXT,
                msWMI_Parm2 TEXT
            )
        """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS printers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                distinguishedName TEXT,
                uNCName TEXT,
                gpoCN TEXT,
                gpoType TEXT
            )
        """
        )

        self.conn.commit()

    def _insert_domain(self, objects):
        for o in objects:
            self.cursor.execute(
                """
                INSERT INTO domain (
                    distinguishedName,
                    objectSid
                ) VALUES (?, ?)
            """,
                (
                    o.get("distinguishedName"),
                    o.get("objectSid"),
                ),
            )

    def _insert_gpos(self, objects):
        for o in objects:
            self.cursor.execute(
                """
                INSERT INTO gpos (
                    distinguishedName,
                    objectGUID,
                    cn,
                    displayName,
                    versionNumber,
                    gPCFileSysPath,
                    gPCMachineExtensionNames,
                    gPCUserExtensionNames,
                    gPCFunctionalityVersion,
                    flags,
                    gPCWQLFilter,
                    nTSecurityDescriptor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    o.get("distinguishedName"),
                    o.get("objectGUID"),
                    o.get("cn"),
                    o.get("displayName"),
                    o.get("versionNumber"),
                    o.get("gPCFileSysPath"),
                    o.get("gPCMachineExtensionNames"),
                    o.get("gPCUserExtensionNames"),
                    o.get("gPCFunctionalityVersion"),
                    o.get("flags"),
                    o.get("gPCWQLFilter"),
                    o.get("nTSecurityDescriptor"),
                ),
            )

    def trustee_type(self, obj_class):
        obj_class = [c.lower() for c in obj_class]

        if "group" in obj_class:
            return "Group"
        elif "computer" in obj_class:
            return "Computer"
        elif "user" in obj_class:
            return "User"
        return None

    def _insert_trustees(self, objects):
        for o in objects:
            self.cursor.execute(
                """
                INSERT INTO trustees (
                    distinguishedName,
                    objectSid,
                    sAMAccountName,
                    type
                ) VALUES (?, ?, ?, ?)
            """,
                (
                    o.get("distinguishedName"),
                    o.get("objectSid"),
                    o.get("sAMAccountName"),
                    self.trustee_type(o.get("objectClass")),
                ),
            )

    def _insert_ous(self, objects):
        for o in objects:
            self.cursor.execute(
                """
                INSERT INTO ous (
                    distinguishedName,
                    objectGUID,
                    name,
                    gPLink,
                    gPOptions
                ) VALUES (?, ?, ?, ?, ?)
            """,
                (
                    o.get("distinguishedName"),
                    o.get("objectGUID"),
                    o.get("name"),
                    o.get("gPLink"),
                    int(o.get("gPOptions", 0)),
                ),
            )

    def _insert_wmi(self, objects):
        for o in objects:
            self.cursor.execute(
                """
                INSERT INTO wmi_filters (
                    distinguishedName,
                    msWMI_ID,
                    msWMI_Name,
                    msWMI_Parm1,
                    msWMI_Parm2,
                    msWMI_Author,
                    msWMI_ChangeDate,
                    msWMI_CreationDate
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    o.get("distinguishedName"),
                    o.get("msWMI-ID"),
                    o.get("msWMI-Name"),
                    o.get("msWMI-Parm1"),
                    o.get("msWMI-Parm2"),
                    o.get("msWMI-Author"),
                    o.get("msWMI-ChangeDate"),
                    o.get("msWMI-CreationDate"),
                ),
            )

    def _insert_printers(self, objects):
        for o in objects:
            dn = o.get("distinguishedName")
            guids = re.findall(r"\{[0-9A-Fa-f-]{36}\}", dn)
            gpo_type = re.search(r",CN=PushedPrinterConnections,CN=(Machine|User)", dn, re.IGNORECASE)

            if len(guids) > 1 and gpo_type:
                gpo_cn = guids[1].upper()
                gpo_type = gpo_type.group(1).capitalize()
            else:
                continue

            self.cursor.execute(
                """
                INSERT INTO printers (
                    distinguishedName,
                    uNCName,
                    gpoCN,
                    gpoType
                ) VALUES (?, ?, ?, ?)
            """,
                (o.get("distinguishedName"), o.get("uNCName"), gpo_cn, gpo_type.capitalize()),
            )

    def insert_dataset(self, dataset):
        for name, objects in dataset.items():
            if name == "domain informations":
                self._insert_domain(objects)

            elif name == "GPOs":
                self._insert_gpos(objects)

            elif name == "trustees":
                self._insert_trustees(objects)

            elif name == "OUs":
                self._insert_ous(objects)

            elif name == "WMI filters":
                self._insert_wmi(objects)

            elif name == "Deployed Printer Connection":
                self._insert_printers(objects)

        self.conn.commit()

    def close(self):
        self.conn.close()
