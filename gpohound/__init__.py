#! /usr/bin/env python3

import argparse
import os
import sys
import logging
from pathlib import Path

from platformdirs import user_config_dir
from gpohound.utils.utils import load_yaml_config
from gpohound.core import GPOHoundCore


def main():

    # Create configuration directory if it does not exist
    os.makedirs(user_config_dir("gpohound"), exist_ok=True)

    # YAML configuration
    file_map = load_yaml_config("config", "gpo_files.yaml")
    neo4j_conf = load_yaml_config("config", "neo4j.yaml")

    parser = argparse.ArgumentParser(description="GPOHound - Group Policy Object Dumper & Analyser")

    # SYSVOL
    sysvol = parser.add_argument_group("SYSVOL source")
    sysvol.add_argument(
        "-S",
        dest="sysvol_path",
        metavar="SYSVOL_PATH",
        default=Path.cwd(),
        type=str,
        help="Path to the SYSVOL directory containing domain GPO data (default: current working directory)",
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

    # Commands
    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    # Dump command
    dump = subparsers.add_parser("dump", help="Dump all GPOs in a structured tree format")
    dump.add_argument("--debug", action="store_true", help="Enable DEBUG output")

    dump_parser = dump.add_argument_group(title="Options")
    dump_parser.add_argument("--gpo-name", action="store_true", help="Resolve and display GPO names")
    dump_parser.add_argument("--list", action="store_true", help="List GPOs")
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
        "--file",
        metavar="",
        help="Filter by file type : " + ", ".join(file_map.keys()),
        choices=file_map.keys(),
        nargs="+",
    )

    # Analysis command
    analysis = subparsers.add_parser("analysis", help="Analyse GPOs and identify potentially interesting settings")
    analysis.add_argument("--debug", action="store_true", help="Enable DEBUG output")

    analysis_parser = analysis.add_argument_group(title="Analysis Options")
    analysis_parser.add_argument(
        "--processed",
        action="store_true",
        help="Display processed settings (group, registry and privilege)",
    )
    analysis_parser.add_argument(
        "--affected",
        action="store_true",
        help="List containers with at least one user or machine affected by a GPO",
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

    analysis_output = analysis.add_argument_group(title="Output options")
    analysis_output.add_argument("--json", action="store_true", help="Format output as JSON")
    analysis_output.add_argument("--gpo-name", action="store_true", help="Resolve and display GPO names")

    analysis_target_parser = analysis.add_argument_group(title="Target object")
    analysis_target_parser.add_argument("--container", metavar="ID/DN", help="Target container (DN or object ID)")
    analysis_target_parser.add_argument("--computer", help="Target machine (machine.domain, DN or SID)")
    analysis_target_parser.add_argument("--user", help="Target user (user@domain, DN or SID)")

    analysis_container_parser = analysis.add_argument_group(title="Target Output")
    analysis_container_parser.add_argument(
        "--order",
        action="store_true",
        help="Show order of applied GPOs for a given container",
    )
    analysis_container_parser.add_argument("--show", action="store_true", help="Display GPO settings of ordered GPOs")

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
        "--file",
        metavar="",
        help="Filter by file : " + ", ".join(file_map.keys()),
        choices=file_map.keys(),
        nargs="+",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    # Logging options
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s: %(message)s")
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if args.debug is True:
        logger.setLevel(logging.DEBUG)

    # Check if the provided GPO file path exists
    if not os.path.exists(args.sysvol_path):
        logging.error("'%s' does not exist.", args.sysvol_path)
        return

    # Set the list of files to parse
    if args.file:
        policy_files = [file_map[file] for file in args.file]
    else:
        policy_files = list(file_map.values())

    # Set the list of domains to parse
    if args.domain:
        domains = [domain.lower() for domain in args.domain]
    else:
        domains = None

    gpohound_core = GPOHoundCore(
        policy_files,
        args.neo4j_host,
        args.neo4j_user,
        args.neo4j_pass,
        args.neo4j_port,
    )

    if args.command == "dump":
        gpohound_core.dump(
            args.sysvol_path,
            domains,
            args.guid,
            args.gpo_name,
            args.json,
            args.list,
            args.search,
            args.show,
        )

    elif args.command == "analysis":
        
        # Bloodhound Ingestor
        if args.enrich_ce:
            ingestor = "bh-ce"
        elif args.enrich:
            ingestor = "bh-legacy"
        else:
            ingestor = ""
        
        gpohound_core.analyser(
            args.sysvol_path,
            domains,
            args.guid,
            args.processed,
            args.affected,
            ingestor,
            args.gpo_name,
            args.order,
            args.show,
            args.object,
            args.container,
            args.computer,
            args.user,
            args.json,
        )

    if gpohound_core.bloodhound_connector.connection:
        gpohound_core.bloodhound_connector.close()
