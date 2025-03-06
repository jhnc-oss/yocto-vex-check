#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os
import subprocess
import unittest
import json
import shutil
import pygit2
import importlib
import logging
from unittest.mock import patch
from json_validate import json_verify


def simple_logger():
    logger = logging.getLogger("CVETestCommands")
    logging.basicConfig(level=logging.INFO)
    logger.setLevel(logging.INFO)
    return logger


yocto_vex_check = importlib.import_module("yocto-vex-check")

current_path = os.path.abspath(__file__)[: -len(os.path.basename(__file__))]
nvd_fetch = os.path.join(current_path, "cve-update-nvd2-native.py")
clone = "https://github.com/mrybczyn/cvelistV5-overrides.git"
branch = "overrides"

test_data_path = os.path.join(current_path, "tests")
build_path = os.path.join(current_path, "tests/build")

data_path = "testdata"
log_path = os.path.join(test_data_path, "tests.log")
nvd_db_dir = os.path.join(current_path, "nvd")
raw_db_dir = os.path.join(current_path, "cve")

cve_from_build_path = os.path.join(test_data_path, "cve-summary-from-build.json")
cve_generated_path = os.path.join(data_path, "cve-summary.json")
vex_generated_path = os.path.join(data_path, "vex-summary.json")
spdx_generated_path = os.path.join(data_path, "spdx-sum.json")


class TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.logger = simple_logger()
        os.makedirs(nvd_db_dir)
        os.makedirs(raw_db_dir)

        subprocess.run(["python", nvd_fetch], cwd=nvd_db_dir)
        self.nvd_path = os.path.join(nvd_db_dir, "tmp/nvdcve_2-1.db")

        pygit2.clone_repository(clone, raw_db_dir, checkout_branch=branch)
        self.cve_path = os.path.join(raw_db_dir, "cves")

        self.true_spdx_commands = [
            [
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "--machine",
                "qemux86-64",
            ],
            ["spdx", "-d", data_path, "-b", build_path, "-m", "qemux86-64"],
            ["spdx", "-d", data_path, "-b", build_path, "--all-machines", "True"],
        ]
        self.true_spdx_commands_interaction = [
            ["spdx", "-d", data_path],
            ["spdx", "-d", data_path, "--all-machines", "True"],
        ]
        self.true_vex_commands = [
            ["vex", "-d", data_path, "-fc", cve_from_build_path],
            ["vex", "--data-path", data_path, "-fc", cve_from_build_path],
            ["vex", "-d", data_path, "--from-cve-file", cve_from_build_path],
            ["vex", "-d", data_path, "-fc", cve_from_build_path, "-l", "debug"],
            ["vex", "-d", data_path, "-fc", cve_from_build_path, "-L", log_path],
        ]
        self.true_cve_commands = [
            [
                "cve",
                "-d",
                data_path,
                "-fc",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "CVE",
                "-db",
                self.cve_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fc",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "CVE",
                "-db",
                self.cve_path,
                "-l",
                "debug",
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fc",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "CVE",
                "-db",
                self.cve_path,
                "-L",
                log_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fs",
                spdx_generated_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "CVE",
                "-db",
                self.cve_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fc",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fc",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
                "-l",
                "debug",
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fc",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
                "-L",
                log_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fs",
                spdx_generated_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "--from-cve-file",
                cve_from_build_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "--from-spdx-file",
                spdx_generated_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
            ],
            [
                "cve",
                "-d",
                data_path,
                "-fs",
                spdx_generated_path,
                "--from-vex-file",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
            ],
            [
                "cve",
                "--version",
                "8.6.0",
                "--product",
                "curl",
                "-d",
                data_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "NVD",
                "-db",
                self.nvd_path,
            ],
            [
                "cve",
                "-v",
                "8.6.0",
                "-p",
                "curl",
                "-d",
                data_path,
                "-fv",
                vex_generated_path,
                "-db-type",
                "CVE",
                "-db",
                self.cve_path,
            ],
        ]
        self.false_commands = [
            ["vex", "-fc", "not/a/path", "-d", data_path],
            ["vex", "-fs", spdx_generated_path, "-l", "not-a-level", "-d", data_path],
            ["vex", "-fc", spdx_generated_path, "-d", data_path],
            ["vex", "-fs", cve_generated_path, "-d", data_path],
            ["cve", "--version", "8.6.0", "-d", data_path],
            ["cve", "-p", "curl", "-d", data_path],
            ["cve", "-fs", spdx_generated_path, "-l", "not-a-level", "-d", data_path],
            ["cve", "-d", data_path],
        ]

    def test_true_spdx_commands(self):
        for cmd in self.true_spdx_commands:
            try:
                yocto_vex_check.main(cmd)
            except SystemExit as e:
                self.assertEqual(e.code, 0, msg=cmd)

            self.assertEqual(
                json_verify(spdx_generated_path, "spdx", self.logger),
                True,
                msg="Malformed SPDX summary",
            )

    @patch("builtins.input", lambda _: build_path, "Y")
    def test_true_spdx_commands_with_interaction(self):
        for cmd in self.true_spdx_commands:
            try:
                yocto_vex_check.main(cmd)
            except SystemExit as e:
                self.assertEqual(e.code, 0, msg=cmd)

            self.assertEqual(
                json_verify(spdx_generated_path, "spdx", self.logger),
                True,
                msg="Malformed SPDX summary",
            )

    def test_true_vex_commands(self):
        for cmd in self.true_vex_commands:
            try:
                yocto_vex_check.main(cmd)
            except SystemExit as e:
                self.assertEqual(e.code, 0, msg=cmd)

            self.assertEqual(
                json_verify(vex_generated_path, "vex", self.logger),
                True,
                msg="Malformed VEX summary",
            )

    def test_true_cve_commands(self):
        for cmd in self.true_cve_commands:
            try:
                yocto_vex_check.main(cmd)
            except SystemExit as e:
                self.assertEqual(e.code, 0, msg=cmd)

            self.assertEqual(
                json_verify(cve_generated_path, "cve", self.logger),
                True,
                msg="Malformed CVE summary",
            )

    def test_false_commands(self):
        for cmd in self.false_commands:
            try:
                yocto_vex_check.main(cmd)
            except SystemExit as e:
                self.assertNotEqual(e.code, 0, msg=cmd)

    @classmethod
    def tearDownClass(self):
        shutil.rmtree(data_path, ignore_errors=True)
        shutil.rmtree(nvd_db_dir, ignore_errors=True)
        shutil.rmtree(raw_db_dir, ignore_errors=True)
        os.remove(log_path)


if __name__ == "__main__":
    unittest.main()
