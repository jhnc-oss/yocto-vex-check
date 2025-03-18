#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
"""Yocto-vex-check entrypoint"""


import argparse
import os
import signal
import sys
import logging

from spdx_fetcher import SpdxFetcher, write_spdx_info
from cve_check import CheckerConfig, cve_check_from_file, do_cve_check_product
from vex import Vex, generate_vex_summary, update_spdx_from_file
from json_validate import json_verify


logger = logging.getLogger(__name__)
default_log_level = "INFO"


def machine_interaction(build_path):
    machine_input = input("Inform machine to use\n(Example: qemux86-64):\n")
    if os.path.exists(os.path.join(build_path, "deploy", "images", machine_input)):
        return machine_input
    else:
        return None


def build_path_interaction(machine, all_machines_flag):
    build_path = input(
        "Inform a absolute path to a build directory\n(Example: /<root>/build/tmp-glibc) :\n"
    )
    if not os.path.exists(build_path):
        return None, machine
    else:
        if not all_machines_flag:
            machine_input = input(
                f"\nYou have chosen {machine} as machine type,\nKeep this {machine} [Y/n] :\n"
            )
            if (
                machine_input == ""
                or machine_input == "Y"
                or machine_input.lower() == "yes"
            ):
                if os.path.exists(
                    os.path.join(build_path, "deploy", "images", machine)
                ):
                    return build_path, machine
                else:
                    machine = None
                    while machine == None:
                        machine = machine_interaction(build_path)
            else:
                machine = None
                while machine == None:
                    machine = machine_interaction(build_path)

            return build_path, machine
        else:
            return build_path, machine


def get_spdx(args=None):
    d = SpdxFetcher()
    d.BASE_PATH = args.data_path

    if args.build_path != None and not os.path.exists(args.build_path):
        logger.error(f"Build path not found ({args.build_path})")
        sys.exit(1)

    machine = args.machine
    if args.build_path == None:
        build_path = None
        while build_path == None:
            build_path, machine = build_path_interaction(
                args.machine, args.all_machines
            )
        d.BUILD_DIR = build_path
        d.setMachine(machine)
    else:
        d.BUILD_DIR = args.build_path
        d.setMachine(args.machine)

    abs_build_path = os.path.join(d.getVar("DEPLOY_DIR"), d.getVar("MACHINE"))
    if not os.path.exists(abs_build_path):
        logger.error(
            f"Deploy path for chosen machine type not found ({abs_build_path})"
        )
        sys.exit(1)

    write_spdx_info(d, logger, args.all_machines)
    return 0


def get_cve(args=None):
    d = CheckerConfig()
    d.setLogger(logger)

    if args.db_type is not None:
        if args.db_type == "CVE":
            d.setDatabaseType("CVE")
        elif args.db_type == "NVD":
            d.setDatabaseType("NVD")
        else:
            logger.error("Unknown database type requested")
            sys.exit(1)

    if args.db is not None:
        db = d.getDatabase(args.db)
    else:
        db = d.getDefaultDatabase()

    if args.data_path != None:
        d.BASE_PATH = args.data_path

    if not os.path.exists(os.path.join(os.getcwd(), args.data_path, "cve", "log")):
        try:
            os.makedirs(os.path.join(os.getcwd(), args.data_path, "cve", "log"))
        except Exception as e:
            logger.error("CVE folder creation failed: {}".format(e))
            db.close()
            sys.exit(1)

    if not os.path.exists(os.path.join(os.getcwd(), args.from_vex_file)):
        logger.error(
            "VEX summary not found in {}".format(
                os.path.join(os.getcwd(), args.from_vex_file)
            )
        )
        db.close()
        sys.exit(1)
    else:
        if json_verify(os.path.join(os.getcwd(), args.from_vex_file), "vex", logger):
            d.setVEXPath(os.path.join(os.getcwd(), args.from_vex_file))
        else:
            db.close()
            sys.exit(1)

    if args.from_spdx_file is not None:
        if os.path.exists(
            os.path.join(os.getcwd(), args.from_spdx_file)
        ) and json_verify(
            os.path.join(os.getcwd(), args.from_spdx_file), "spdx", logger
        ):
            d.setSPDXPath(os.path.join(os.getcwd(), args.from_spdx_file))
        else:
            logger.error(
                "SPDX summary not found in {}".format(
                    os.path.join(os.getcwd(), args.from_spdx_file)
                )
            )
            db.close()
            sys.exit(1)

    if args.from_cve_file is not None:
        if os.path.exists(
            os.path.join(os.getcwd(), args.from_cve_file)
        ) and json_verify(os.path.join(os.getcwd(), args.from_cve_file), "cve", logger):
            d.setCVEPath(os.path.join(os.getcwd(), args.from_cve_file))
        else:
            logger.error(
                "CVE summary not found in {}".format(
                    os.path.join(os.getcwd(), args.from_cve_file)
                )
            )
            db.close()
            sys.exit(1)

    try:
        if args.product != None and args.version != None:
            do_cve_check_product(d, None, args.product, args.version)
        else:
            cve_check_from_file(d)
    except Exception as e:
        logger.error("CVE check failed: {}".format(e))
        db.close()
        sys.exit(1)

    db.close()
    return 0


def get_vex(args=None):

    d = Vex()

    if args.data_path != None:
        d.BASE_PATH = args.data_path

    if args.from_cve_file is None and not os.path.exists(
        os.path.join(d.getVar("BASE_PATH"), d.getVar("CVE_CHECK_LOG_JSON"))
    ):
        logger.error("No cve file found")
        logger.error(
            "Please run either yocto-vex-check.py cve -f <filename> or yocto-vex-check.py cve -p <name> -v <version>"
        )
        sys.exit(1)
    elif args.from_cve_file is None and os.path.exists(
        os.path.join(d.getVar("BASE_PATH"), d.getVar("CVE_CHECK_LOG_JSON"))
    ):
        if json_verify(
            os.path.join(d.getVar("BASE_PATH"), d.getVar("CVE_CHECK_LOG_JSON")),
            "cve",
            logger,
        ):
            d.setCvePath(
                os.path.join(d.getVar("BASE_PATH"), d.getVar("CVE_CHECK_LOG_JSON"))
            )
        else:
            sys.exit(1)

    if args.from_cve_file is not None:
        if os.path.exists(
            os.path.join(d.getVar("BASE_PATH"), args.from_cve_file)
        ) and json_verify(
            os.path.join(d.getVar("BASE_PATH"), args.from_cve_file), "cve", logger
        ):
            d.setCvePath(os.path.join(d.getVar("BASE_PATH"), args.from_cve_file))
        elif os.path.exists(args.from_cve_file) and json_verify(
            args.from_cve_file, "cve", logger
        ):
            d.setCvePath(args.from_cve_file)
        else:
            logger.error(
                f"CVE summary filename given not found\n"
                "Inform absolute path to cve summary file or"
                " inform relative path from data folder"
            )
            return 1

    generate_vex_summary(d, logger)

    if args.update_spdx:
        if os.path.exists(args.build_path) and os.path.exists(
            os.path.join(args.build_path, "deploy", "spdx", args.arch)
        ):
            d.setBuildPath(args.build_path)
            d.setArch(args.arch)

            update_spdx_from_file(d, logger)
        else:
            logger.error(
                "Deploy path for chosen architecture type not found "
                f'({os.path.join(args.build_path, "deploy", "spdx", args.arch)})'
            )

    return 0


def create_parser():
    parser = argparse.ArgumentParser(description="Yocto-vex-check - get VEXs and CVEs")

    parser.set_defaults(func=None)

    subparser = parser.add_subparsers(
        title="subcommands", description="valid subcommands", help="additional help"
    )

    spdxparser = subparser.add_parser("spdx", help="Extract SPDX data from deploy dir")
    spdxparser.add_argument(
        "-b",
        "--build-path",
        default=None,
        required=False,
        help="Build path (example: %s)" % "/<root>/build/tmp-glibc",
    )
    spdxparser.add_argument(
        "-m",
        "--machine",
        default="qemux86-64",
        required=False,
        help="Machine (default: qemux86-64)",
    )
    spdxparser.add_argument(
        "--all-machines",
        default=False,
        required=False,
        help="Get SPDX information for every architectures found",
    )
    spdxparser.set_defaults(func=get_spdx)

    cveparser = subparser.add_parser(
        "cve",
        help="Extract CVEs and store into JSON file."
        "\nUsing either SPDX summary or CVE summary and VEX summary"
        " default path is data/cve-summary.json",
    )
    cveparser.add_argument(
        "-fs",
        "--from-spdx-file",
        default=None,
        help="Export CVE with spdx summary input.\n"
        "Required if cve-summary.json is not used as input.",
        required=bool("--from-cve-file" not in sys.argv) and bool("-fc" not in sys.argv),
    )
    cveparser.add_argument(
        "-fc",
        "--from-cve-file",
        default=None,
        help="Export CVE with cve summary input.\n"
        "Required if spdx-sum.json is not used as input.",
        required=bool("--from-spdx-file" not in sys.argv) and bool("-fs" not in sys.argv),
    )
    cveparser.add_argument(
        "-fv",
        "--from-vex-file",
        default=None,
        help="Export CVE with vex summary input",
        required=True,
    )
    cveparser.add_argument(
        "-p",
        "--product",
        default=None,
        help="Export CVE for specific product (specify product name and version)",
        required="--version" in sys.argv or "-v" in sys.argv,
    )
    cveparser.add_argument(
        "-v",
        "--version",
        default=None,
        help="Export CVE for specific product (specify product name and version)",
        required="--product" in sys.argv or "-p" in sys.argv,
    )
    cveparser.add_argument(
        "-db", default=None, help="Absolute path to database dump", required=False
    )
    cveparser.add_argument(
        "-db-type",
        default="NVD",
        help="Vulnerability database to use: CVE or NVD (default)",
        required=False,
    )
    cveparser.set_defaults(func=get_cve)

    vexparser = subparser.add_parser(
        "vex",
        help="Extract VEX data from CVE and SPDX data"
        " default path is data/vex-summary.json",
    )
    vexparser.add_argument(
        "-fc",
        "--from-cve-file",
        default=None,
        help="Use cve summary to generate VEX files"
        "\nUse either relative path from data folder or absolute path to cve summary file\n"
        " (default: %s)" % "<data folder>/cve-summary.json",
        required=False,
    )
    vexparser.add_argument(
        "-u",
        "--update-spdx",
        default=False,
        help="Update SPDX files with VEX id",
        required=False,
    )
    vexparser.add_argument(
        "-b",
        "--build-path",
        default=None,
        required="--update-spdx" in sys.argv or "-u" in sys.argv,
        help="Build path (example: %s)" % "/<root>/build/tmp-glibc",
    )
    vexparser.add_argument(
        "-a",
        "--arch",
        default="qemux86_64",
        required="--update-spdx" in sys.argv or "-u" in sys.argv,
        help="Sstate architecture (default: qemux86_64)",
    )
    vexparser.set_defaults(func=get_vex)

    for sp in [spdxparser, cveparser, vexparser]:
        sp.add_argument(
            "-l",
            "--log-level",
            choices=["debug", "info", "warning", "error", "critical"],
            default=default_log_level,
            help="Set log level (default: %s)" % default_log_level,
        )
        sp.add_argument(
            "-L", "--log-file", dest="logfilename", nargs=1, help="Log to file"
        )
        sp.add_argument(
            "-d", "--data-path", default="data", help="Export folder", required=True
        )

    return parser


def interruption(signum, frame):
    signame = signal.Signals(signum).name
    logger.warning(f"Signal handler called with signal {signame}")
    sys.exit(0)


def main():
    global default_log_level
    FORMAT = "[%(asctime)s %(filename)s->%(funcName)s():%(lineno)s]%(levelname)s: %(message)s"
    logging.basicConfig(format=FORMAT, level=default_log_level)

    signal.signal(signal.SIGINT, interruption)
    signal.signal(signal.SIGTERM, interruption)

    parser = create_parser()
    args = parser.parse_args()

    if args.func is None:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(os.path.join(os.getcwd(), args.data_path)):
        try:
            os.makedirs(os.path.join(os.getcwd(), args.data_path))
        except Exception as e:
            logger.error("Data folder creation aborted: {}".format(e))
            sys.exit(1)

    if args.log_level:
        default_log_level = args.log_level.upper()

    logging.basicConfig(format=FORMAT, level=default_log_level)

    if args.logfilename:
        fh = logging.FileHandler(args.logfilename[0])
        fh.setLevel(default_log_level)
        logger.addHandler(fh)

    try:
        args.func(args)
    except Exception as e:
        logger.error("Failed: {}".format(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
