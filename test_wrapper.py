#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os, sys
import unittest
import pytest
from subprocess import Popen, PIPE

import importlib

oe_wrapper = importlib.import_module("oe-wrap-vuln-check")


class TestWrapper(unittest.TestCase):
    data_path = "testdata"
    output_dir = "test_output"
    build_path = "/".join(os.path.abspath(__file__).split("/")[:-1]) + "/tests/build"
    cve_path_from_build = (
        "/".join(os.path.abspath(__file__).split("/")[:-1])
        + "/tests/cve-summary-from-build.json"
    )
    wrapper_path = (
        "/".join(os.path.abspath(__file__).split("/")[:-1]) + "/oe-wrap-vuln-check.py"
    )
    db_path = (
        "/".join(os.path.abspath(__file__).split("/")[:-1]) + "/tests/nvdcve_2-1.db"
    )

    def test_wrap_command(self):
        p = Popen(
            [
                "python",
                self.wrapper_path,
                "-i",
                self.cve_path_from_build,
                "-o",
                self.output_dir,
                "-t",
                self.data_path,
                "-b",
                self.build_path,
                "-db",
                self.db_path,
            ]
        )
        code = p.wait()

        self.assertEqual(0, code)
