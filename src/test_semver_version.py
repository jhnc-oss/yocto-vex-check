#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os, sys
import unittest
import json
from databases import is_semver
from databases import match_semver_less
from databases import match_semver_equal
from databases import match_semver_less_equal
from databases import match_semver_greater


class TestSemverVersion(unittest.TestCase):
    versions = ["0", "-", "1.0", "1.0.0", "1.*", "*", "unspecified", "4.22.132"]
    false_versions = ["1.1.1.1", "1.0.2b", "1.0.2-dev", "not-a-version"]
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
            self.assertEqual(is_semver(v), True)
        for el in self.false_versions:
            self.assertEqual(is_semver(el), False)

    def test_is_greater(self):
        for v in self.greater_version:
            self.assertEqual(match_semver_greater(v["limit"], v["version"]), True)
        for v in self.false_greater_versions:
            self.assertEqual(match_semver_greater(v["limit"], v["version"]), False)

    def test_is_lesser(self):
        for v in self.lesser_version:
            self.assertEqual(match_semver_less(v["limit"], v["version"]), True)
        for v in self.false_lesser_versions:
            self.assertEqual(match_semver_less(v["limit"], v["version"]), False)

    def test_is_equal(self):
        for v in self.equal_version:
            self.assertEqual(match_semver_equal(v["limit"], v["version"]), True)
        for v in self.false_lesser_versions:
            self.assertEqual(match_semver_equal(v["limit"], v["version"]), False)


if __name__ == "__main__":
    unittest.main()
