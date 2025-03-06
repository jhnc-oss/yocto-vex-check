#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
"""OE wrapper for the cve tooling"""

import argparse
import os
import sys
import subprocess
import shutil
from pathlib import Path

# Example sequence:
# python yocto-vex-check.py spdx -b ../../oe-core/build/tmp-glibc/ -d data_input/
# cp /oe-core/build/tmp-glibc/log/cve/cve-summary.json data_input/
# python yocto-vex-check.py vex -fc cve-summary.json -d data_input/
# python yocto-vex-check.py cve -fs data_input/spdx-sum.json -fv data_input/vex-summary.json -d data_output/


def main(argv):
    parser = argparse.ArgumentParser(
        description="wrap-yocto-vex-check - Wrap vulnerabiliy checking for OE-core"
    )
    parser.add_argument(
        "-i", "--input-file", default=None, required=True, help="Input JSON CVE file"
    )
    parser.add_argument(
        "-o", "--output-dir", default=None, required=True, help="Output VEX file"
    )
    parser.add_argument(
        "-t", "--input-temporary-dir", required=True, help="Temporary input dir"
    )
    parser.add_argument(
        "-b",
        "--build-dir",
        default=None,
        required=False,
        help="Build directory to get SPDX data from",
    )
    parser.add_argument(
        "-db", default=None, required=False, help="Absolute path to database dump"
    )
    parser.add_argument(
        "-db-type",
        default="NVD",
        required=False,
        help="Vulnerability database to use: CVE or NVD (default)",
    )

    args = parser.parse_args(argv)

    scan_tool = os.path.join(
        os.path.dirname(os.path.realpath(sys.argv[0])), "yocto-vex-check.py"
    )

    try:
        use_package_list_cve = True
        # Create the directory if it does not exist
        if not os.path.exists(args.input_temporary_dir):
            os.makedirs(args.input_temporary_dir)

        if args.build_dir:
            use_package_list_cve = False
            print("Coping SPDX files")
            output = subprocess.run(
                [scan_tool, "spdx", "-b", args.build_dir, "-d", args.input_temporary_dir],
                capture_output=True,
                text=True,
            )
            if output.returncode:
                print(output.stderr)
                sys.exit(1)

        print("Copying the CVE JSON file")
        shutil.copy(args.input_file, args.input_temporary_dir)

        input_file_name = Path(args.input_file).name

        print("Converting CVE JSON to input VEX")
        output = subprocess.run(
            [
                scan_tool,
                "vex",
                "-fc",
                os.path.join(args.input_temporary_dir, input_file_name),
                "-d",
                args.input_temporary_dir,
            ],
            capture_output=True,
            text=True,
        )
        if output.returncode:
            print(output.stderr)
            sys.exit(1)

        print("Grabbing CVE information")
        if use_package_list_cve:
            output = subprocess.run(
                [
                    scan_tool,
                    "cve",
                    "-fc",
                    os.path.join(args.input_temporary_dir, input_file_name),
                    "-fv",
                    os.path.join(args.input_temporary_dir, "vex-summary.json"),
                    "-d",
                    args.output_dir,
                    "-db",
                    args.db,
                    "-db-type",
                    args.db_type,
                ],
                capture_output=True,
                text=True,
            )
        else:
            output = subprocess.run(
                [
                    scan_tool,
                    "cve",
                    "-fs",
                    os.path.join(args.input_temporary_dir, "spdx-sum.json"),
                    "-fv",
                    os.path.join(args.input_temporary_dir, "vex-summary.json"),
                    "-d",
                    args.output_dir,
                    "-db",
                    args.db,
                    "-db-type",
                    args.db_type,
                ],
                capture_output=True,
                text=True,
            )
        if output.returncode:
            print(output.stderr)
            sys.exit(1)
        print("CVE check finished")

    except subprocess.CalledProcessError:
        print("Error running command: " + output.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
