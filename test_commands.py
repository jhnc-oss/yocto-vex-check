#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os, sys
import unittest
import pytest
import json
from parameterized import parameterized

import importlib

yocto_vex_check = importlib.import_module("yocto-vex-check")


class TestCommands(unittest.TestCase):
    data_path = "testdata"
    build_path = "/".join(os.path.abspath(__file__).split("/")[:-1]) + "/tests/build"
    spdx_path = os.path.join(data_path, "spdx-sum.json")
    cve_path = os.path.join(data_path, "cve-summary.json")
    cve_path_from_build = (
        "/".join(os.path.abspath(__file__).split("/")[:-1])
        + "/tests/cve-summary-from-build.json"
    )
    vex_path = os.path.join(data_path, "vex-summary.json")
    db_path = (
        "/".join(os.path.abspath(__file__).split("/")[:-1]) + "/tests/nvdcve_2-1.db"
    )
    db_type = "NVD"

    @parameterized.expand(
        [
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "--machine",
                "qemux86-64",
            ),
            ("spdx", "-d", data_path, "-b", build_path, "-m", "qemux86-64"),
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "--all-machines",
                "True",
            ),
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "--machine",
                "qemux86-64",
                "-L",
                "test.log",
            ),
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "--machine",
                "qemux86-64",
                "-l",
                "error",
                "-L",
                "test.log",
            ),
        ]
    )
    @pytest.mark.order(1)
    def test_true_spdx_commands(self, *argv):
        try:
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(0)

    @parameterized.expand(
        [
            ("spdx", "--data-path", data_path),
            ("spdx", "--data-path", data_path, "--all-archs", "True"),
        ]
    )
    @pytest.mark.order(2)
    def test_true_spdx_commands_inputs(self, *argv):
        try:
            yocto_vex_check.input = lambda: self.build_path, "Y"
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(0)

    @parameterized.expand(
        [
            ("spdx", "--data-path", data_path, "-m", "not-a-machine"),
            (
                "spdx",
                "--data-path",
                data_path,
                "-m",
                "not-a-machine",
                "--all-machines",
                "True",
            ),
        ]
    )
    @pytest.mark.order(3)
    def test_false_spdx_commands_inputs(self, *argv):
        try:
            yocto_vex_check.input = (
                lambda: self.build_path + "/not/a/path",
                self.build_path,
                "Y",
            )
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(1)

        try:
            yocto_vex_check.input = (
                lambda: "/".join(self.build_path.split("/")[2:]),
                "Y",
            )
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(1)

    @parameterized.expand(
        [
            ("spdx"),
            ("spdx", "--build-path", build_path, "-m", "qemux86-64"),
            ("spdx", "--data-path", data_path, "-m", "-l", "debug"),
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "-L",
                "test.log",
            ),
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                "/build/tmp-glibc",
                "--arch",
                "core2-64",
            ),
            (
                "spdx",
                "--data-path",
                data_path,
                "--build-path",
                build_path,
                "--machine",
                "qemux86-64",
                "-l",
                "not-a-log-level",
            ),
        ]
    )
    @pytest.mark.order(4)
    def test_false_spdx_commands(self, *argv):
        try:
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(1)

    @parameterized.expand(
        [
            ("vex", "-fc", cve_path_from_build, "-d", data_path),
            ("vex", "--from-cve-file", cve_path_from_build, "-d", data_path),
            ("vex", "-fc", cve_path_from_build, "-l", "info", "-d", data_path),
            ("vex", "-fc", cve_path_from_build, "-L", "testcve.log", "-d", data_path),
            ("vex", "-fc", cve_path_from_build, "-u", "-d", data_path),
        ]
    )
    @pytest.mark.order(5)
    def test_true_vex_commands(self, *argv):
        try:
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(0)

    @parameterized.expand(
        [
            ("vex", "-fc", "not/a/path", "-d", data_path),
            ("vex", "-fc", spdx_path, "-l", "not-a-level", "-d", data_path),
            ("vex", "-fc", spdx_path, "-d", "not/a/path"),
        ]
    )
    @pytest.mark.order(6)
    def test_false_vex_commands(self, *argv):
        try:
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(1)

    @parameterized.expand(
        [
            ("cve", "-fs", "/tmp", "-d", data_path),
            ("cve", "-fs", spdx_path, "-l", "not-a-level", "-d", data_path),
            ("cve", "-p", "curl", "-d", data_path),
            ("cve", "--version", "8.6.0", "-d", data_path),
            ("cve", "--product", "curl", "--version", "-fv", vex_path, "8.6.0"),
        ]
    )
    @pytest.mark.order(7)
    def test_false_cve_commands(self, *argv):
        try:
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(1)

    @parameterized.expand(
        [
            (
                "cve",
                "-fs",
                spdx_path,
                "-fv",
                vex_path,
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
            (
                "cve",
                "--from-spdx-file",
                spdx_path,
                "--from-vex-file",
                vex_path,
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
            (
                "cve",
                "-fs",
                spdx_path,
                "-fv",
                vex_path,
                "-l",
                "info",
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
            (
                "cve",
                "-fs",
                spdx_path,
                "-fv",
                vex_path,
                "-L",
                "testcve.log",
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
            (
                "cve",
                "-p",
                "curl",
                "-v",
                "8.6.0",
                "-fs",
                spdx_path,
                "-fv",
                vex_path,
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
            (
                "cve",
                "--product",
                "curl",
                "--version",
                "8.6.0",
                "-fs",
                spdx_path,
                "-fv",
                vex_path,
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
            (
                "cve",
                "-fs",
                spdx_path,
                "-fv",
                vex_path,
                "-d",
                data_path,
                "-db-type",
                db_type,
                "-db",
                db_path,
            ),
        ]
    )
    @pytest.mark.order(8)
    def test_true_cve_commands(self, *argv):
        try:
            yocto_vex_check.main(argv)
        except SystemExit as e:
            assert SystemExit(0)
