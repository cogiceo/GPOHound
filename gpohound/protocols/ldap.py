import base64
import logging
import traceback
from uuid import UUID

from rich.live import Live
from rich.spinner import Spinner
from rich.console import Console
from impacket.ldap.ldap import LDAPConnection, LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry, SDFlagsControl, SimplePagedResultsControl, Scope
from impacket.dcerpc.v5.dtypes import SID

console = Console(highlight=False)


class LDAPUtils:

    def __init__(
        self,
        dc_host,
        domain,
        logon_domain,
        username,
        password,
        lmhash,
        nthash,
        do_kerberos,
        aeskey,
        use_ldaps,
    ):
        self.kdc_host = dc_host
        self.domain = domain
        self.logon_domain = logon_domain if logon_domain else self.domain
        self.username = username
        self.password = password if password else ""
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.aeskey = aeskey
        self.ldaps_flag = use_ldaps

        self.base_dn = ",".join(f"DC={part}" for part in domain.split("."))

    def connect(self, base_dn):
        """
        Establishes and returns a connection to the LDAP server.
        """

        if self.ldaps_flag:
            prefix = "ldaps://"
        else:
            prefix = "ldap://"

        ldap_conn = LDAPConnection(f"{prefix}{self.kdc_host}", self.kdc_host)
        ldap_conn.searchBase = base_dn

        # Authentication
        if self.do_kerberos:
            ldap_conn.kerberosLogin(
                self.username,
                self.password,
                self.logon_domain,
                self.lmhash,
                self.nthash,
                self.aeskey,
                kdcHost=self.kdc_host,
            )
        else:
            ldap_conn.login(self.username, self.password, self.logon_domain, self.lmhash, self.nthash)
        return ldap_conn

    def get_forest_root_dn(self, base_dn):
        """
        Get the DN of the forest root LDAP server.
        """
        ldap_conn = self.connect(base_dn)
        try:
            # LDAP query
            result = ldap_conn.search(
                searchBase="",
                scope=Scope("baseObject"),
                attributes=["rootDomainNamingContext"],
            )
            for raw_entry in result:
                if isinstance(raw_entry, SearchResultEntry):
                    for attr in raw_entry["attributes"]:
                        return str(attr["vals"][0])
        except LDAPSearchError as e:
            logging.error(f"Search failed on {base_dn}: {e}")

        return None

    def query(self, ldap_conn, search_dn, filter, attributes_filter=None):
        """
        Dumps all LDAP objects under the specified base distinguished name
        """
        entries = []
        searchControls = []
        searchControls.append(SDFlagsControl())
        searchControls.append(SimplePagedResultsControl(size=200))

        spinner = Spinner("line", text="Querying objects...")
        with Live(spinner, refresh_per_second=10, console=console, transient=True):
            processed_count = 0
            try:
                # LDAP query
                result = ldap_conn.search(
                    searchBase=search_dn,
                    searchFilter=filter,
                    attributes=attributes_filter,
                    searchControls=searchControls,
                )

                # Parse LDAP objects
                for raw_entry in result:

                    if isinstance(raw_entry, SearchResultEntry):
                        entry = {}

                        for attr in raw_entry["attributes"]:
                            attr_type = str(attr["type"])
                            values = []

                            if attr_type == "objectSid":
                                sid = SID(bytes(attr["vals"][0]))
                                entry[attr_type] = sid.formatCanonical()
                            elif attr_type == "objectGUID":
                                guid = UUID(bytes_le=bytes(attr["vals"][0]))
                                entry[attr_type] = str(guid)
                            elif attr_type in ["msWMI-Parm1", "msWMI-Parm2"]:
                                entry[attr_type] = str(attr["vals"][0])
                            else:
                                for value in attr["vals"]:
                                    decoded_value = bytes(value).decode(errors="ignore")
                                    if decoded_value.isprintable():
                                        values.append(decoded_value)
                                    else:
                                        values.append(base64.b64encode(bytes(value)).decode())
                                entry[attr_type] = values if len(values) > 1 else values[0]  # flatten if single value

                        entries.append(entry)
                        processed_count += 1

                console.print(f"  [green bold][+][/] Found {processed_count} objects")

            except LDAPSearchError as e:
                console.print(f"  [red bold][-][/] Search failed on {search_dn}")
                logging.info(e)
                logging.debug(traceback.format_exc)
        return entries
