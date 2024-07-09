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
from databases import match_semver_less_equal
from databases import match_semver_greater


class SemverTest(unittest.TestCase):
    true_versions = ["1.1", "1.0.2", "1.25.3", "17.1.1", "4.1.57", "0", "unspecified"]
    false_versions = ["1.1.1.1", "1.0.2b", "1.0.2-dev", "not-a-version"]
    equal_versions = [
        ["1.1", "1.1.0"],
        ["1", "1.0.0"],
        ["2.3.4", "2.3.4"],
    ]
    # Last element is smaller than the first one
    less_versions = [
        ["1.1", "1.0.2"],
        ["2.0", "1.3.2"],
        ["2.0", "0"],
    ]
    # Last element is greater than the first one
    greater_versions = [
        ["3.5.12", "3.6.1"],
        ["3.5.12", "4.0"],
        ["3.5", "3.5.1"],
    ]

    def test_is_semver(self):
        for el in self.true_versions:
            self.assertEqual(is_semver(el), True)
        for el in self.false_versions:
            self.assertEqual(is_semver(el), False)

    def test_is_less(self):
        for el in self.less_versions:
            self.assertEqual(match_semver_less(el[0], el[1]), True)
        for el in self.less_versions:
            self.assertEqual(match_semver_less(el[1], el[0]), False)
        for el in self.equal_versions:
            self.assertEqual(match_semver_less(el[0], el[1]), False)

    def test_is_greater(self):
        for el in self.greater_versions:
            self.assertEqual(match_semver_greater(el[0], el[1]), True)
        for el in self.greater_versions:
            self.assertEqual(match_semver_greater(el[1], el[0]), False)
        for el in self.equal_versions:
            self.assertEqual(match_semver_less(el[0], el[1]), False)

    def test_is_less_equal(self):
        for el in self.less_versions + self.equal_versions:
            self.assertEqual(match_semver_less_equal(el[0], el[1]), True)
        for el in self.greater_versions:
            self.assertEqual(match_semver_less_equal(el[0], el[1]), False)


if __name__ == "__main__":
    unittest.main()
