#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import unittest
import traceback
from versions import SemanticVersioning


class TestSemverVersion(unittest.TestCase):
    versions = ["0", "-", "1.0", "1.0.0", "1.*", "*", "unspecified", "4.22.132"]
    false_versions = ["1.1.1.1", "1.0.2b", "1.0.2-dev", "not-a-version"]

    #version is greather then limit
    greater_version = [
        {"version": "1.1", "limit": "1.0"},
        {"version": "1.0.1", "limit": "1.0"},
        {"version": "1.0", "limit": "-"},
        {"version": "1.0", "limit": "0"},
        {"version": "1.0", "limit": "1.*"},
        {"version": "1.0", "limit": "*"},
        {"version": "3.6.1", "limit": "3.5.12"},
        {"version": "4.0", "limit": "3.5.12"},
        {"version": "3.5.1", "limit": "3.5"},
    ]

    #version is lesser then limit
    lesser_version = [
        {"version": "1.0", "limit": "2.*"},
        {"version": "1.0", "limit": "2.0"},
        {"version": "1.0", "limit": "1.0.2"},
        {"version": "1.0", "limit": "1.0.*"},
        {"version": "1.0", "limit": "1.*"},
        {"version": "1.0", "limit": "*"},
        {"version": "1.0.2", "limit": "1.1"},
        {"version": "1.3.2", "limit": "2.0"},
        {"version": "0", "limit": "2.0"},
    ]
    equal_version = [
        {"version": "1.0", "limit": "1.0"},
        {"version": "1.0", "limit": "1.0.0"},
        {"version": "1.1", "limit": "1.1.0"},
        {"version": "1", "limit": "1.0.0"},
        {"version": "0", "limit": "0.0.0"},
    ]
    # Last element is smaller than the first one
    false_lesser_versions = [
        {"version": "2.0", "limit": "1.*"},
        {"version": "2.0", "limit": "1.0"},
        {"version": "1.0.2", "limit": "1.0"},
        {"version": "1.1", "limit": "1.0.2"},
    ]
    # Last element is greater than the first one
    false_greater_versions = [
        {"version": "1.0", "limit": "1.1"},
        {"version": "1.0", "limit": "1.0.1"},
        {"version": "1.0", "limit": "2.*"},
        {"version": "3.5.12", "limit": "3.6.1"},
        {"version": "3.5", "limit": "3.5.1"},
        {"version": "0", "limit": "1.0.0"},
    ]

    def test_is_semver(self):
        for v in self.versions:
            try:
                SemanticVersioning(v)
            except Exception:
                traceback.print_exc()
                self.fail(v + "was falsly identifyed as unsupportet version")

        for el in self.false_versions:
                self.assertRaises(ValueError, SemanticVersioning, el)

    def test_is_greater(self):
        for v in self.greater_version:
            self.assertTrue(SemanticVersioning(v["version"]) > SemanticVersioning(v["limit"]))
        for v in self.false_greater_versions:
            self.assertFalse(SemanticVersioning(v["version"]) > SemanticVersioning(v["limit"]))

    def test_is_lesser(self):
        for v in self.lesser_version:
            self.assertTrue(SemanticVersioning(v["version"]) < SemanticVersioning(v["limit"]))
        for v in self.false_lesser_versions:
            self.assertFalse(SemanticVersioning(v["version"]) < SemanticVersioning(v["limit"]))

    def test_is_equal(self):
        for v in self.equal_version:
            self.assertEqual(SemanticVersioning(v["version"]) == SemanticVersioning(v["limit"]),True)
            self.assertEqual(SemanticVersioning(v["limit"]) == SemanticVersioning(v["version"]),True)

        for v in self.false_lesser_versions:
            self.assertEqual(SemanticVersioning(v["version"]) == SemanticVersioning(v["limit"]),False)
            self.assertEqual(SemanticVersioning(v["limit"]) == SemanticVersioning(v["version"]),False)


if __name__ == "__main__":
    unittest.main()
