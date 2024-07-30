#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os, sys
import unittest
import json
from databases import compute_openssl_version
from databases import is_supported_custom
from databases import match_custom_less
from databases import match_custom_less_equal
from databases import match_custom_greater


class OpenSSLVersionTest(unittest.TestCase):
    versions = [
        {"version": "1.1", "result": tuple([(1, 1, 0), (), 1])},
        {"version": "1.0.2", "result": tuple([(1, 0, 2), (), 1])},
        {"version": "1.0.2b", "result": tuple([(1, 0, 2), (98,), 1])},
        {"version": "1.0.2b-dev", "result": tuple([(1, 0, 2), (98,), 0])},
        {"version": "1.0.2-dev", "result": tuple([(1, 0, 2), (), 0])},
        {"version": "1.1.1.1", "result": tuple([(1, 1, 1, 1), (), 1])},
        {"version": "1.1.1.1k", "result": tuple([(1, 1, 1, 1), (107,), 1])},
        {"version": "1.1.1.1-dev", "result": tuple([(1, 1, 1, 1), (), 0])},
        {"version": "1.1.1.1k-dev", "result": tuple([(1, 1, 1, 1), (107,), 0])},
    ]

    def test_version_supported(self):
        for el in self.versions:
            self.assertEqual(is_supported_custom(el["version"]), True)

    def test_versionning(self):
        for el in self.versions:
            self.assertEqual(compute_openssl_version(el["version"]), el["result"])

    def test_greater(self):
        # Last argument should be greater than the first one
        self.assertEqual(match_custom_greater("1.0.2", "1.1"), True)
        self.assertEqual(match_custom_greater("1.0.2-dev", "1.0.2"), True)
        self.assertEqual(match_custom_greater("1.0.2a", "1.0.2b"), True)
        self.assertEqual(match_custom_greater("1.0.2a-dev", "1.0.2a"), True)
        self.assertEqual(match_custom_greater("1.1.1", "1.1.1.1"), True)
        self.assertEqual(match_custom_greater("1.1.1f", "1.1.1.1"), True)
        self.assertEqual(match_custom_greater("1.1.1", "0"), False)
        self.assertEqual(match_custom_greater("0", "1.1.1"), True)

    def test_less(self):
        # Last argument should be smaller than the first one
        self.assertEqual(match_custom_less("1.1", "1.0.2"), True)
        self.assertEqual(match_custom_less("1.0.2-dev", "1.0.2"), True)
        self.assertEqual(match_custom_less("1.0.2b", "1.0.2a"), True)
        self.assertEqual(match_custom_less("1.0.2a", "1.0.2a-dev"), True)
        self.assertEqual(match_custom_less("1.1.1.1", "1.1.1"), True)
        self.assertEqual(match_custom_less("1.1.1.1", "1.1.1f"), True)
        self.assertEqual(match_custom_less("1.1.1.1", "0"), True)
        self.assertEqual(match_custom_less("0", "1.1.1.1"), False)

    def test_less_equal(self):
        # Last argument should be smaller than the first one or equal
        self.assertEqual(match_custom_less_equal("1.1", "1.0.2"), True)
        self.assertEqual(match_custom_less_equal("1.1", "1.1.0"), True)
        self.assertEqual(match_custom_less_equal("1.0.2", "1.1"), False)
        self.assertEqual(match_custom_less_equal("1.0.2-dev", "1.0.2"), True)
        self.assertEqual(match_custom_less_equal("1.0.2b", "1.0.2a"), True)
        self.assertEqual(match_custom_less_equal("1.0.2a", "1.0.2a"), True)
        self.assertEqual(match_custom_less_equal("1.0.2a", "1.0.2a-dev"), True)
        self.assertEqual(match_custom_less_equal("1.0.2a", "1.1.1"), False)


if __name__ == "__main__":
    unittest.main()
