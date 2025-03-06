#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os, sys
import unittest
import json
import logging
from cve_check import CheckerConfig
from cve_check import do_cve_check

# In order to run this test a temporary folder should be set as well as fetching a nvd dump
temp_folder = "testdata"
db_path = "/".join(os.path.abspath(__file__).split("/")[:-1]) + "/tests/nvdcve_2-1.db"


class SimpleLogger:
    logger = logging.getLogger("CPETest")
    default_log_level = "DEBUG"


def generate_cve_checker(cpes):

    checker = CheckerConfig()
    checker.CVE_PRODUCT = "curl"
    checker.CVE_PACKAGE = "curl-native"
    checker.CVE_VERSION = "8.6.0"
    checker.CPE_table = cpes
    checker.setLogger(SimpleLogger().logger)
    checker.setDatabaseType("NVD")
    checker.getDatabase(db_path)
    checker.setVEXTable([])
    checker.BASE_PATH = temp_folder

    return checker


def get_issues(checker):
    data = {}

    do_cve_check(checker)

    with open(f'{checker.getVar("CVE_CHECK_LOG_JSON")}') as f:
        data = json.load(f)
    os.remove(f'{checker.getVar("CVE_CHECK_LOG_JSON")}')

    return data["package"][0]["issue"]


class CPETest(unittest.TestCase):

    dancurl_check = generate_cve_checker(
        ["cpe:2.3:*:daniel_stenberg:curl:8.6.0:*:*:*:*:*:*:*"]
    )
    haxxcurl_check = generate_cve_checker(["cpe:2.3:*:haxx:curl:8.6.0:*:*:*:*:*:*:*"])
    curl_check = generate_cve_checker(["cpe:2.3:*:curl:curl:8.6.0:*:*:*:*:*:*:*"])
    combined_check = generate_cve_checker(
        [
            "cpe:2.3:*:curl:curl:8.6.0:*:*:*:*:*:*:*",
            "cpe:2.3:*:daniel_stenberg:curl:8.6.0:*:*:*:*:*:*:*",
            "cpe:2.3:*:haxx:curl:8.6.0:*:*:*:*:*:*:*",
        ]
    )

    dancurl_issues = get_issues(dancurl_check)
    haxxcurl_issues = get_issues(haxxcurl_check)
    curl_issues = get_issues(curl_check)
    combined_issues = get_issues(combined_check)

    def test_product_with_multiple_cpes(self):
        self.assertEqual(len(self.dancurl_issues), len(self.haxxcurl_issues))
        self.assertEqual(len(self.dancurl_issues), len(self.curl_issues))
        self.assertEqual(len(self.haxxcurl_issues), len(self.curl_issues))

        manual_combined = self.dancurl_issues + self.haxxcurl_issues + self.curl_issues
        manual_cves = list({v["id"]: v for v in manual_combined}.values())
        self.assertEqual(len(self.combined_issues), len(manual_cves))


if __name__ == "__main__":
    unittest.main()
