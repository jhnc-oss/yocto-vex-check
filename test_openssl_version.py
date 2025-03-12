#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
import traceback
import unittest
from versions import OpenSSLVersioning, SemanticVersioning

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
            try:
                OpenSSLVersioning(el["version"])
            except Exception:
                traceback.print_exc()
                self.fail("Detected unsupportet version")

    def test_versionning(self):
        for el in self.versions:
            osv = OpenSSLVersioning(el["version"])
            self.assertEqual(osv._OpenSSLVersioning__normalize_open_ssl(el["version"]), el["result"])

    def test_greater(self):
        # Firs argument should be greater than the second one
        self.assertEqual(OpenSSLVersioning("1.1") > OpenSSLVersioning("1.0.2"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2") > OpenSSLVersioning("1.0.2-dev"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2b") > OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") > OpenSSLVersioning("1.0.2a-dev"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1.1") > OpenSSLVersioning("1.1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1.1") > OpenSSLVersioning("1.1.1f"), True)
        self.assertEqual(OpenSSLVersioning("0") > OpenSSLVersioning("1.1.1"), False)
        self.assertEqual(OpenSSLVersioning("1.1.1") > OpenSSLVersioning("0"), True)


    def test_less(self):
        # First argument should be smaller than the second one
        self.assertEqual(OpenSSLVersioning("1.0.2") < OpenSSLVersioning("1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2-dev") < OpenSSLVersioning("1.0.2"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") < OpenSSLVersioning("1.0.2b"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a-dev") < OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1") < OpenSSLVersioning("1.1.1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1f") < OpenSSLVersioning("1.1.1.1"), True)
        self.assertEqual(OpenSSLVersioning("0") < OpenSSLVersioning("1.1.1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1.1") < OpenSSLVersioning("0"), False)

    def test_less_equal(self):
        # First argument should be smaller than the second one or equal
        self.assertEqual(OpenSSLVersioning("1.0.2") <= OpenSSLVersioning("1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.1.0") <= OpenSSLVersioning("1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.1") <= OpenSSLVersioning("1.0.2"), False)
        self.assertEqual(OpenSSLVersioning("1.0.2-dev") <= OpenSSLVersioning("1.0.2"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") <= OpenSSLVersioning("1.0.2b"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") <= OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a-dev") <= OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1") <= OpenSSLVersioning("1.0.2a"), False)


    def test_greater_equal(self):
        # First argument should be greater than or equal to the second one
        self.assertEqual(OpenSSLVersioning("1.1") >= OpenSSLVersioning("1.0.2"), True)
        self.assertEqual(OpenSSLVersioning("1.1") >= OpenSSLVersioning("1.1.0"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2") >= OpenSSLVersioning("1.1"), False)
        self.assertEqual(OpenSSLVersioning("1.0.2") >= OpenSSLVersioning("1.0.2-dev"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2b") >= OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") >= OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") >= OpenSSLVersioning("1.0.2a-dev"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") >= OpenSSLVersioning("1.1.1"), False)

    def test_equal(self):
        # First argument should be equal to the second one
        self.assertEqual(OpenSSLVersioning("1.1") == OpenSSLVersioning("1.1.0"), True)
        self.assertEqual(OpenSSLVersioning("1.1") == OpenSSLVersioning("1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2") == OpenSSLVersioning("1.0.2"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2-dev") == OpenSSLVersioning("1.0.2-dev"), True)
        self.assertEqual(OpenSSLVersioning("1.0.2a") == OpenSSLVersioning("1.0.2a"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1") == OpenSSLVersioning("1.1.1"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1f") == OpenSSLVersioning("1.1.1f"), True)
        self.assertEqual(OpenSSLVersioning("0") == OpenSSLVersioning("0"), True)
        self.assertEqual(OpenSSLVersioning("1.1.1.1") == OpenSSLVersioning("1.1.1.1"), True)

    def test_comparison_with_semantic_versioning(self):
        # Assuming SemanticVersioning is another versioning class
        semantic_version = SemanticVersioning("1.1.0")
        openssl_version = OpenSSLVersioning("1.1.0")

        # Test comparison between OpenSSLVersioning and SemanticVersioning
        with self.assertRaises(TypeError):
            _ = openssl_version > semantic_version
        with self.assertRaises(TypeError):
            _ = openssl_version < semantic_version
        with self.assertRaises(TypeError):
            _ = openssl_version >= semantic_version
        with self.assertRaises(TypeError):
            _ = openssl_version <= semantic_version
        with self.assertRaises(TypeError):
            _ = openssl_version == semantic_version

    def test_comparison_with_non_versioning_objects(self):
        openssl_version = OpenSSLVersioning("1.1.0")

        # Test comparison with non-versioning objects
        with self.assertRaises(TypeError):
            _ = openssl_version > "1.1.0"
        with self.assertRaises(TypeError):
            _ = openssl_version < "1.1.0"
        with self.assertRaises(TypeError):
            _ = openssl_version >= "1.1.0"
        with self.assertRaises(TypeError):
            _ = openssl_version <= "1.1.0"
        with self.assertRaises(TypeError):
            _ = openssl_version == "1.1.0"

    def test_comparison_with_none(self):
        openssl_version = OpenSSLVersioning("1.1.0")

        # Test comparison with None
        with self.assertRaises(TypeError):
            _ = openssl_version > None
        with self.assertRaises(TypeError):
            _ = openssl_version < None
        with self.assertRaises(TypeError):
            _ = openssl_version >= None
        with self.assertRaises(TypeError):
            _ = openssl_version <= None
        with self.assertRaises(TypeError):
            _ = openssl_version == None


if __name__ == "__main__":
    unittest.main()
