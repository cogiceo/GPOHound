from rich.console import Console
from gpohound.utils.sqlite import LDAPDatabaseBuilder

console = Console(highlight=False)


class LDAPDumper:
    """
    Class to dump the LDAP informations
    """

    def __init__(self, ldap_utils, db_path, overwrite):
        self.ldap_utils = ldap_utils
        self.db_path = db_path
        self.overwrite = overwrite

        # [MS-GPOL] - Section 2.2
        self.ldap_queries = {
            self.ldap_utils.base_dn: [
                {
                    "domain informations": {
                        "filter": "(objectClass=domain)",
                        "attributes": [
                            "distinguishedName",
                            "objectSid",
                        ],
                    },
                    "GPOs": {
                        "filter": "(objectClass=groupPolicyContainer)",
                        "attributes": [
                            "distinguishedName",
                            "nTSecurityDescriptor",
                            "objectGUID",
                            "cn",
                            "displayName",
                            "gPCFileSysPath",
                            "versionNumber",
                            "gPCMachineExtensionNames",
                            "gPCUserExtensionNames",
                            "gPCFunctionalityVersion",
                            "flags",
                            "gPCWQLFilter",
                        ],
                    },
                },
                {
                    "trustees": {
                        "filter": "(|(objectClass=User)(objectClass=Group)(objectClass=Computer))",
                        "attributes": ["distinguishedName", "objectSid", "sAMAccountName", "objectClass"],
                    }
                },
                {
                    "OUs": {
                        "filter": "(|(objectClass=OrganizationalUnit)(objectClass=domain)(&(objectClass=container)(|(cn=Users)(cn=Computers)(cn=ForeignSecurityPrincipals)(cn=Managed Service Accounts))))",
                        "attributes": ["distinguishedName", "objectGUID", "name", "gPLink", "gPOptions"],
                    }
                },
            ],
            f"CN=SOM,CN=WMIPolicy,CN=System,{self.ldap_utils.base_dn}": [
                {
                    "WMI filters": {
                        "filter": "(objectClass=msWMI-Som)",
                        "attributes": [
                            "distinguishedName",
                            "msWMI-ID",
                            "msWMI-Name",
                            "msWMI-Parm1",
                            "msWMI-Author",
                            "msWMI-ChangeDate",
                            "msWMI-CreationDate",
                            "msWMI-Parm2",
                        ],
                    }
                }
            ],
            f"CN=Policies,CN=System,{self.ldap_utils.base_dn}": [
                {
                    "Deployed Printer Connection": {
                        "filter": "(objectClass=msPrint-ConnectionPolicy)",
                        "attributes": ["distinguishedName", "uNCName"],
                    }
                }
            ],
        }

    def dump(self):
        """
        Dumps the LDAP objects
        """

        results = {}

        for search_dn, query_groups in self.ldap_queries.items():
            ldap_conn = self.ldap_utils.connect(search_dn)

            for query_group in query_groups:
                for query_name, query in query_group.items():
                    results.setdefault(query_name, {})
                    console.print(f"[underline]Querying {query_name} under {search_dn}[/]")
                    data = self.ldap_utils.query(
                        ldap_conn=ldap_conn,
                        search_dn=search_dn,
                        filter=query["filter"],
                        attributes_filter=query["attributes"],
                    )

                    results[query_name] = data
        if results:
            ldap_sqlite = LDAPDatabaseBuilder(self.db_path, self.overwrite)
            ldap_sqlite.init_db()
            ldap_sqlite.insert_dataset(results)
            ldap_sqlite.close()
            console.print(f"\nSuccessfully dumped LDAP data to '{self.db_path}'")
        else:
            console.print(f"\nNo LDAP results found")
