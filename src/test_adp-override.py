#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os
import json
import unittest
import shutil
import subprocess

current_path = os.path.abspath(__file__)[: -len(os.path.basename(__file__))]
cna_database_path = os.path.join(current_path, "rawcna/1234/5xxx")
adp_database_path = os.path.join(current_path, "rawadp/1234/5xxx")
output_dir = os.path.join(current_path, "testdata")
cve_summary_reference_path = os.path.join(output_dir, "source-cve-summary.json")
empty_vex_path = os.path.join(output_dir, "vex-summary.json")

yocto_vex_check = os.path.join(current_path, "yocto-vex-check.py")


class TestAdpOverride(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        mockCVE = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "vendorA",
                            "product": "product",
                            "versions": [
                                {
                                    "version": "1.0.0-1.1.0",
                                    "status": "affected",
                                    "versionType": "semver",
                                }
                            ],
                        }
                    ],
                    "descriptions": [{"lang": "en", "value": "Mock CVE"}],
                },
            },
        }
        # Setup cna-only database
        os.makedirs(cna_database_path)
        with open(f"{cna_database_path}/CVE-1234-5678.json", "w") as f:
            json.dump(mockCVE, f)

        mockCVEadp = mockCVE
        mockCVEadp["containers"]["adp"] = [
            {
                "title": "CISA ADP Vulnrichment",
                "metrics": [
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "id": "CVE-1234-5678",
                                "role": "CISA Coordinator",
                                "options": [
                                    {"Exploitation": "none"},
                                    {"Automatable": "no"},
                                    {"Technical Impact": "partial"},
                                ],
                                "version": "2.0.3",
                            },
                        }
                    }
                ],
                "affected": [
                    {
                        "cpes": [
                            "cpe:2.3:a:vendorA:product:*:*:*:*:*:*:*:*",
                            "cpe:2.3:a:vendorB:product:*:*:*:*:*:*:*:*",
                        ],
                        "vendor": "vendorA",
                        "product": "product",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "1.0.0",
                                "versionType": "semver",
                                "lessThanOrEqual": "1.1.0",
                            }
                        ],
                        "defaultStatus": "unaffected",
                    }
                ],
            }
        ]
        mockCVE2 = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "vendorB",
                            "product": "product",
                            "versions": [
                                {
                                    "version": "2.0.0",
                                    "status": "affected",
                                    "versionType": "semver",
                                }
                            ],
                        }
                    ],
                    "descriptions": [{"lang": "en", "value": "Mock CVE2"}],
                },
            },
        }

        # Setup cna-adp database
        os.makedirs(adp_database_path)
        with open(f"{adp_database_path}/CVE-1234-5678.json", "w") as f:
            json.dump(mockCVEadp, f)
        with open(f"{adp_database_path}/CVE-1234-5679.json", "w") as f:
            json.dump(mockCVE2, f)

        mock_cve_summary = {
            "version": "1",
            "package": [
                {
                    "name": "product",
                    "layer": "meta",
                    "version": "1.0.2",
                    "products": [{"product": "product", "cvesInRecord": "No"}],
                    "cpes": ["cpe:2.3:*:vendorA:product:1.0.2:*:*:*:*:*:*:*"],
                    "issue": [],
                }
            ],
        }
        os.makedirs(output_dir)

        # Setup mock summary
        with open(cve_summary_reference_path, "w") as f:
            json.dump(mock_cve_summary, f)

        # Get vex summary
        subprocess.run(
            [
                yocto_vex_check,
                "vex",
                "-fc",
                cve_summary_reference_path,
                "-d",
                output_dir,
            ]
        )

        self.cve_cna_command = [
            yocto_vex_check,
            "cve",
            "-fv",
            empty_vex_path,
            "-fc",
            cve_summary_reference_path,
            "-d",
            output_dir,
            "-db-type",
            "CVE",
            "-db",
            os.path.join(current_path, "rawcna"),
        ]
        self.cve_adp_command = [
            yocto_vex_check,
            "cve",
            "-fv",
            empty_vex_path,
            "-fc",
            cve_summary_reference_path,
            "-d",
            output_dir,
            "-db-type",
            "CVE",
            "-db",
            os.path.join(current_path, "rawadp"),
        ]

    def test_cna_malformed_cve(self):
        output = subprocess.run(
            self.cve_cna_command,
            capture_output=True,
            text=True,
        )
        self.assertEqual("Malformed entry... skipping" in output.stderr, True)

        original_summary = {}
        output_summary = {}
        with open(cve_summary_reference_path) as f:
            original_summary = json.load(f)
        with open(os.path.join(output_dir, "cve-summary.json")) as f:
            output_summary = json.load(f)

        original_issues = original_summary["package"][0]["issue"]
        original_cpes = original_summary["package"][0]["cpes"]

        output_issues = output_summary["package"][0]["issue"]
        output_cpes = output_summary["package"][0]["cpes"]

        # Assert malformed CVE has been ruled as "Unknown"
        self.assertEqual(output_issues[0]["status"], "Unknown")
        # Assert CPEs has not changed
        self.assertEqual(len(output_cpes), len(original_cpes))
        self.assertEqual(output_cpes, original_cpes)

    def test_adp_addition(self):
        output = subprocess.run(
            self.cve_adp_command,
            capture_output=True,
            text=True,
        )
        self.assertEqual(output.returncode, 0)

        original_summary = {}
        output_summary = {}
        with open(cve_summary_reference_path) as f:
            original_summary = json.load(f)
        with open(os.path.join(output_dir, "cve-summary.json")) as f:
            output_summary = json.load(f)

        original_issues = original_summary["package"][0]["issue"]
        original_cpes = original_summary["package"][0]["cpes"]

        output_issues = output_summary["package"][0]["issue"]
        output_cpes = output_summary["package"][0]["cpes"]
        output_cve5678 = [el for el in output_issues if el["id"] == "CVE-1234-5678"]
        output_cve5679 = [el for el in output_issues if el["id"] == "CVE-1234-5679"]

        # Assert fixed adp version of CVE has been used compared to cna version
        self.assertNotEqual(len(output_issues), len(original_issues))
        # Assert CVE has been ruled as "Unpatched"
        self.assertEqual(len(output_cve5678), 1)
        self.assertEqual(output_cve5678[0]["status"], "Unpatched")
        # Assert CPEs contained in adp container is present
        self.assertNotEqual(len(output_cpes), len(original_cpes))
        # Assert each CPE is different from one another
        self.assertEqual(len(output_cpes), len(list(set(output_cpes))))
        # Assert CVE-1234-5679 is present
        self.assertEqual(len(output_cve5679), 1)

    @classmethod
    def tearDownClass(self):
        shutil.rmtree(os.path.join(current_path, "rawcna"))
        shutil.rmtree(os.path.join(current_path, "rawadp"))
        shutil.rmtree(output_dir)


if __name__ == "__main__":
    unittest.main()
