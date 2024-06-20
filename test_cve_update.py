#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os, sys
import unittest
import json
from databases import cve_is_ignored
from databases import cve_is_patched
from databases import cve_update
import logging


class SimpleLogger:
    logger = logging.getLogger("CVEUpdateTest")
    default_log_level = "DEBUG"


class CVEUpdateTest(unittest.TestCase):

    def test_cve_is_ignored(self):
        cve_data = {}
        cve_data["CVE-1995-001"] = {}
        cve_data["CVE-1995-001"]["abbrev-status"] = "Ignored"
        cve_data["CVE-1995-002"] = {}
        cve_data["CVE-1995-002"]["abbrev-status"] = "Patched"
        # Typo
        cve_data["CVE-1995-003"] = {}
        cve_data["CVE-1995-003"]["avvrev-status"] = "Ignored"

        self.assertEqual(cve_is_ignored(None, cve_data, "CVE-1995-001"), True)
        self.assertEqual(cve_is_ignored(None, cve_data, "CVE-1995-002"), False)
        self.assertEqual(cve_is_ignored(None, cve_data, "CVE-1995-003"), False)
        # Not-exiting entry
        self.assertEqual(cve_is_ignored(None, cve_data, "blah"), False)
        self.assertEqual(cve_is_ignored(None, cve_data, "CVE-2024-10000"), False)

    def test_cve_is_patched(self):
        cve_data = {}
        cve_data["CVE-1995-001"] = {}
        cve_data["CVE-1995-001"]["abbrev-status"] = "Ignored"
        cve_data["CVE-1995-002"] = {}
        cve_data["CVE-1995-002"]["abbrev-status"] = "Patched"
        # Typo
        cve_data["CVE-1995-003"] = {}
        cve_data["CVE-1995-003"]["avvrev-status"] = "Patched"

        self.assertEqual(cve_is_patched(None, cve_data, "CVE-1995-001"), False)
        self.assertEqual(cve_is_patched(None, cve_data, "CVE-1995-002"), True)
        self.assertEqual(cve_is_patched(None, cve_data, "CVE-1995-003"), False)
        # Not-exiting entry
        self.assertEqual(cve_is_patched(None, cve_data, "blah"), False)
        self.assertEqual(cve_is_patched(None, cve_data, "CVE-2024-10000"), False)

    def test_cve_update(self):
        d = SimpleLogger()
        cve_data = {}
        cve_data["CVE-1995-001"] = {}
        cve_data["CVE-1995-001"]["abbrev-status"] = "Ignored"
        cve_data["CVE-1995-002"] = {}
        cve_data["CVE-1995-002"]["abbrev-status"] = "Patched"
        cve_data["CVE-1995-002"]["status"] = "version-not-in-range"

        cve_update(
            d,
            cve_data,
            "CVE-1995-001",
            {"abbrev-status": "Patched", "status": "version-not-in-range"},
        )
        # The entry has not been updated, Ignored has priority
        self.assertEqual(cve_data["CVE-1995-001"]["abbrev-status"], "Ignored")

        # Simple insert
        cve_update(
            d,
            cve_data,
            "CVE-1995-004",
            {"abbrev-status": "Patched", "status": "version-not-in-range"},
        )
        self.assertEqual(cve_data["CVE-1995-004"]["abbrev-status"], "Patched")
        self.assertEqual(cve_data["CVE-1995-004"]["status"], "version-not-in-range")

        # Simple insert
        cve_update(
            d,
            cve_data,
            "CVE-1995-005",
            {"abbrev-status": "Unpatched", "status": "version-in-range"},
        )
        self.assertEqual(cve_data["CVE-1995-005"]["abbrev-status"], "Unpatched")
        self.assertEqual(cve_data["CVE-1995-005"]["status"], "version-in-range")

        # Insert "Unknown"
        cve_update(d, cve_data, "CVE-1995-006", {"abbrev-status": "Unknown"})
        self.assertEqual(cve_data["CVE-1995-006"]["abbrev-status"], "Unknown")

        # Insert the same entry, should be no change
        cve_update(
            d,
            cve_data,
            "CVE-1995-005",
            {"abbrev-status": "Unpatched", "status": "version-in-range"},
        )
        self.assertEqual(cve_data["CVE-1995-005"]["abbrev-status"], "Unpatched")
        self.assertEqual(cve_data["CVE-1995-005"]["status"], "version-in-range")

        # Update Unknown with Unpatched
        cve_update(
            d,
            cve_data,
            "CVE-1995-006",
            {"abbrev-status": "Unpatched", "status": "version-in-range"},
        )
        self.assertEqual(cve_data["CVE-1995-006"]["abbrev-status"], "Unpatched")
        self.assertEqual(cve_data["CVE-1995-006"]["status"], "version-in-range")

        # Update Patched to Unpatched
        cve_update(
            d,
            cve_data,
            "CVE-1995-002",
            {"abbrev-status": "Unpatched", "status": "version-in-range"},
        )
        self.assertEqual(cve_data["CVE-1995-002"]["abbrev-status"], "Unpatched")
        self.assertEqual(cve_data["CVE-1995-002"]["status"], "version-in-range")

        # Try update Ignored to Unpatched -> should have no impact
        cve_update(
            d,
            cve_data,
            "CVE-1995-001",
            {"abbrev-status": "Unpatched", "status": "version-in-range"},
        )
        self.assertEqual(cve_data["CVE-1995-001"]["abbrev-status"], "Ignored")


if __name__ == "__main__":
    unittest.main()
