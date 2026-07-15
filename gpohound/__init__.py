#! /usr/bin/env python3

import argparse
import sys
import logging
from pathlib import Path

from gpohound.utils.utils import load_yaml_config, is_ip
from gpohound.protocols.smb import SMBUtils
from gpohound.protocols.ldap import LDAPUtils
from gpohound.dumper.sysvol import SYSVOLDumper
from gpohound.dumper.ldap import LDAPDumper
from gpohound.cli import GPOHoundCLI
from gpohound.core import GPOHoundCore

from rich.console import Console
from rich.logging import RichHandler
from platformdirs import user_config_dir


console = Console(highlight=False)


def main():

    # Create configuration directory if it does not exist
    Path(user_config_dir("gpohound")).mkdir(parents=True, exist_ok=True)

    # YAML configuration
    policy_map = load_yaml_config("config", "gpo_policies.yaml")
    neo4j_conf = load_yaml_config("config", "neo4j.yaml")

    parser = argparse.ArgumentParser(description="GPOHound - Group Policy Object Dumper & Analyser")

    # SYSVOL & LDAP sources
    sources = parser.add_argument_group("SYSVOL and LDAP dump sources")
    sources.add_argument(
        "-S",
        dest="sysvol_path",
        metavar="SYSVOL_PATH",
        default="gpos/sysvols",
        type=str,
        help="Path to to the folder containing the SYSVOL of domains (default: gpos/sysvols)",
    )

    sources.add_argument(
        "-L",
        dest="ldap_path",
        metavar="LDAP_PATH",
        default="gpos/ldap",
        type=str,
        help="Path to the folder containing the LDAP sqlite databases (default: gpos/ldap)",
    )

    # Neo4j configuration
    neo4j = parser.add_argument_group("Neo4j settings")
    neo4j.add_argument(
        "--neo4j-host",
        default=neo4j_conf.get("neo4j-host"),
        metavar="HOST",
        help=f"IP address or hostname of the Neo4j server (default: {neo4j_conf.get('neo4j-host')})",
    )
    neo4j.add_argument(
        "--neo4j-port",
        default=neo4j_conf.get("neo4j-port"),
        metavar="PORT",
        help=f"Port used by Neo4j's Bolt protocol (default: {str(neo4j_conf.get('neo4j-port'))})",
        type=int,
    )
    neo4j.add_argument(
        "--neo4j-user",
        default=neo4j_conf.get("neo4j-user"),
        metavar="USER",
        help=f"Username for Neo4j authentication (default: {neo4j_conf.get('neo4j-user')})",
    )
    neo4j.add_argument(
        "--neo4j-pass",
        default=neo4j_conf.get("neo4j-pass"),
        metavar="PASS",
        help=f"Password for Neo4j authentication (default: {neo4j_conf.get('neo4j-pass')})",
    )

    # verbosity arguments (parent)
    verbosity_parent = argparse.ArgumentParser(add_help=False)
    verbosity_parent.add_argument("--debug", action="store_true", help="Enable DEBUG output")
    verbosity_parent.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Authentication arguments (parent)
    auth_parent = argparse.ArgumentParser(add_help=False)
    auth_parser = auth_parent.add_argument_group(title="Connection")
    auth_parser.add_argument("--dc", type=str, help="Domain Controller IP address or hostname", required=True)
    auth_parser.add_argument("-d", "--domain", type=str, help="Target domain name", required=True)
    auth_parser.add_argument("-u", "--username", type=str, help="[Domain/]Username for authentication", required=True)
    auth_parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    auth_parser.add_argument("-H", "--hashes", type=str, help="NTLM hashes (LMHASH:NTHASH)")
    auth_parser.add_argument(
        "-k", "--kerberos", action="store_true", help="Use Kerberos authentication (Requires hostname)"
    )
    auth_parser.add_argument("--aeskey", type=str, help="AES key for Kerberos authentication")

    # Commands
    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    # SYSVOL command
    sysvol_parser = subparsers.add_parser(
        "sysvol", parents=[verbosity_parent, auth_parent], help="Download the SYSVOL share"
    )
    sysvol_parser.add_argument(
        "-o", "--output", type=str, default="gpos/sysvols", help="Output folder (default: gpos/sysvols)"
    )
    smb_parser = sysvol_parser.add_argument_group(title="Filters")
    smb_parser.add_argument("-m", "--max-size", type=float, help="Maximum size of file to download (in MB)")
    smb_parser.add_argument(
        "-e", "--exclude", type=str, help="Comma-separated regex of paths to exclude (ex: '/Policydefinitions/')"
    )
    smb_parser.add_argument(
        "-i", "--include", type=str, help="Comma-separated regexes of paths to download (ex: '/Scripts/')"
    )
    smb_parser.add_argument("-g", "--gpos", action="store_true", help="Download only GPO files")
    smb_parser.add_argument("-a", "--analysis", action="store_true", help="Download only GPOs that will be analysed")

    # LDAP command
    ldap_parser = subparsers.add_parser("ldap", parents=[auth_parent], help="Dump LDAP data")
    ldap_parser.add_argument("-o", "--output", type=str, default="gpos/ldap", help="Output folder (default: gpos/ldap)")
    ldap_parser.add_argument("--overwrite", action="store_true", help="Overwrite the existing database file")
    ldap_args_parser = ldap_parser.add_argument_group(title="LDAP flags")
    connection_type = ldap_args_parser.add_mutually_exclusive_group()
    connection_type.add_argument("--ldaps", action="store_true", help="Use LDAPS (port 636)")

    # Parse command
    parse = subparsers.add_parser("parse", parents=[verbosity_parent], help="Parse a single GPO file")
    parse_options = parse.add_argument_group(title="Filters")
    parse_options.add_argument("file", metavar="gpo-file", type=str, help="Path to the GPO file")
    parse_options.add_argument("--json", action="store_true", help="Format output as JSON")

    # Dump command
    dump = subparsers.add_parser("dump", parents=[verbosity_parent], help="Dump all GPOs in a structured tree format")
    dump_parser = dump.add_argument_group(title="Options")
    dump_parser.add_argument("--list", action="store_true", help="List GPOs")
    dump_parser.add_argument(
        "--affected",
        action="store_true",
        help="List non-empty affected OUs (user/computer counts by default, names in JSON output)",
    )
    dump_parser.add_argument("--json", action="store_true", help="Display results in JSON format")
    search_parser = dump.add_argument_group(title="Search")
    search_parser.add_argument("--search", help="Search for a regex pattern in key and value")
    search_parser.add_argument(
        "--show",
        action="store_true",
        help="Display the values associated with search hits",
    )
    dump_filters = dump.add_argument_group(title="Filters")
    dump_filters.add_argument("--domain", metavar="", help="Filter by one or more domains", nargs="+")
    dump_filters.add_argument("--guid", metavar="", help="Filter by one or more GPO GUIDs", nargs="+")
    dump_filters.add_argument(
        "--policies",
        metavar="",
        help="Filter by policy type : " + ", ".join(policy_map.keys()),
        choices=policy_map.keys(),
        nargs="+",
    )

    # Analysis command
    analysis = subparsers.add_parser(
        "analysis", parents=[verbosity_parent], help="Analyse GPOs and identify potentially interesting settings"
    )
    analysis_output = analysis.add_argument_group(title="Output options")
    analysis_output.add_argument("--json", action="store_true", help="Format output as JSON")
    analysis_parser = analysis.add_argument_group(title="Analysis Options")
    analysis_parser.add_argument(
        "--affected",
        action="store_true",
        help="List non-empty affected OUs (user/computer counts by default, names in JSON output)",
    )
    analysis_parser.add_argument(
        "--enrich",
        action="store_true",
        help="Augment BloodHound data with additional relationships/properties",
    )
    analysis_parser.add_argument(
        "--enrich-ce",
        action="store_true",
        help="Same as --enrich, but persists the groups relationships on BloodHound-CE (takes longer to run)",
    )
    analysis_target_parser = analysis.add_argument_group(title="Target an object")
    analysis_target_parser.add_argument("--ou", metavar="ID/DN", help="Target OU (DN or object ID)")
    analysis_target_parser.add_argument("--trustee", help="Target trustee (user@domain, machine.domain, DN or SID)")
    analysis_target_parser.add_argument(
        "--list",
        action="store_true",
        help="List GPOs in order for specified target",
    )
    analysis_target_parser.add_argument(
        "--dump", action="store_true", help="Dump GPO settings in order for a specified target"
    )

    analysis_objects = [
        "group",
        "registry",
        "privilege",
        "gpppassword",
    ]
    analysis_filters = analysis.add_argument_group(title="Filters")
    analysis_filters.add_argument("--domain", metavar="", help="Filter by one or more domains", nargs="+")
    analysis_filters.add_argument("--guid", metavar="", help="Filter by one or more GPO GUIDs", nargs="+")
    analysis_filters.add_argument(
        "--object",
        metavar="",
        help="Filter by object : " + ", ".join(analysis_objects),
        choices=analysis_objects,
        nargs="+",
    )
    analysis_filters.add_argument(
        "--policies",
        metavar="",
        help="Filter by policy type : " + ", ".join(policy_map.keys()),
        choices=policy_map.keys(),
        nargs="+",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    # Logging options
    if getattr(args, "debug", False):
        level = logging.DEBUG
    elif getattr(args, "verbose", False):
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                show_path=getattr(args, "debug", False),
            )
        ],
    )

    if level != logging.DEBUG:
        logging.getLogger("impacket").disabled = True

    # SYSVOL and LDAP dump
    if args.command in ["sysvol", "ldap"]:
        if args.kerberos and is_ip(args.dc):
            console.print("Kerberos authentication requires hostname of the DC instead of an IP")
            sys.exit()

        domain = args.domain.lower()

        if "/" in args.username:
            logon_domain, username = args.username.rsplit("/", 1)
        else:
            username = args.username
            logon_domain = args.domain

        if args.hashes:
            lmhash, nthash = args.hashes.split(":")
        else:
            lmhash, nthash = "", ""

        # SYSVOL dump
        if args.command == "sysvol":
            smb_utils = SMBUtils(
                args.dc, logon_domain, username, args.password, lmhash, nthash, args.kerberos, args.aeskey
            )

            if not smb_utils.smbClient:
                console.print("Failed to connect to the SMB server.")
                return

            sysvol_dumper = SYSVOLDumper(
                smb_utils,
                args.include,
                args.exclude,
                args.max_size,
                args.gpos,
                args.analysis,
                args.output,
            )
            sysvol_dumper.download()

        # LDAP dump
        if args.command == "ldap":
            db_path = Path(args.output) / f"{domain}.sqlite"

            if not args.overwrite and db_path.exists():
                console.print(f"Database '{db_path}' already exists, use --overwrite")
                return

            ldap_utils = LDAPUtils(
                args.dc,
                args.domain,
                logon_domain,
                username,
                args.password,
                lmhash,
                nthash,
                args.kerberos,
                args.aeskey,
                args.ldaps,
            )
            ldap_dumper = LDAPDumper(ldap_utils, db_path, args.overwrite)
            ldap_dumper.dump()

    # Operation on GPOs
    elif args.command in ["dump", "analysis", "parse"]:

        # Check if the provided LDAP fodler path exists
        if not Path(args.ldap_path).exists():
            logging.info(f"'{args.ldap_path}' LDAP folder does not exist.")
            ldap_path = None
        else:
            ldap_path = args.ldap_path

        if args.command in ["dump", "analysis"]:

            # Check if the provided GPO path exists
            if not Path(args.sysvol_path).exists():
                console.print(f"'{args.sysvol_path}' SYSVOLS folder does not exist.")
                return

            # Set the list of files to parse
            if args.policies:
                selected_policies = [policy_map[policy] for policy in args.policies]
            else:
                selected_policies = list(policy_map.values())

            # Set the list of domains to parse
            if args.domain:
                domains = [domain.lower() for domain in args.domain]
            else:
                domains = None

            if args.guid:
                guids = ["{" + guid.upper().strip("{").strip("}") + "}" for guid in args.guid]
            else:
                guids = None

        else:
            selected_policies = list(policy_map.values())

        # Init core engine of GPOHound
        core = GPOHoundCore(
            selected_policies,
            ldap_path,
            args.sysvol_path,
            args.neo4j_host,
            args.neo4j_user,
            args.neo4j_pass,
            args.neo4j_port,
        )

        if args.command in ["dump", "analysis", "parse"]:
            cli = GPOHoundCLI(core, args.json)

            # Parse one GPO file
            if args.command == "parse":
                if not Path(args.file).exists():
                    console.print(f"'{args.file}' does not exist.")
                    return

                if Path(args.file).is_dir():
                    console.print(f"'{args.file}' is a directory, expected a file.")
                    return

                cli.parse_gpo_file(args.file)

            # Dump GPOs
            elif args.command == "dump":
                if args.list:
                    cli.list_gpos(domains, guids)
                elif args.search:
                    cli.search_gpo_settings(domains, guids, args.search, args.show)
                else:
                    cli.dump_gpos_settings(domains, guids, args.affected)

            # Analyse GPO
            elif args.command == "analysis":
                if args.enrich or args.enrich_ce:

                    if not core.bloodhound.connection:
                        console.print("This command requires a working BloodHound connection")
                        return

                    if not core.bloodhound.apoc:
                        console.print("Enable the Neo4j APOC plugin: ", end="")
                        console.print("'cp /var/lib/neo4j/labs/apoc-* /var/lib/neo4j/plugins/ && neo4j restart'")
                        return

                if args.affected and not (core.bloodhound.connection or core.sqlite_handler.dbs):
                    console.print("This command requires a working BloodHound connection or an LDAP dump")
                    return

                # Enrich Bloodhound data
                if args.enrich_ce or args.enrich:
                    ingestor = "bh-ce" if args.enrich_ce else "bh-legacy"
                    cli.enrich_bh(ingestor, domains, guids)

                # Target a specific OU or trustee
                elif args.trustee or args.ou:
                    object = args.ou if args.ou else args.trustee
                    type = "ou" if args.ou else "trustee"

                    if args.dump:
                        cli.dump_gpo_applied_on_object(object, type, args.affected)
                    elif args.list:
                        cli.list_gpos_applied_on_object(object, type)
                    else:
                        cli.analyse_gpos_applied_on_object(object, type, args.object)

                # Analyse GPOs
                else:
                    cli.analyse_gpos(domains, guids, args.object, args.affected)

        if core.bloodhound.connection:
            core.bloodhound.close()
