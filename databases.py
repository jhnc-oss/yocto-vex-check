#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
from abc import abstractmethod
from enum import Enum
#from cve_check import CheckerConfig

class VexStatus(Enum):
    UNAFFECTED = 'unaffected'
    UNDER_INVESTIGATION = 'under_investigation'
    FIXED = 'fixed'
    AFFECTED = 'affected'
    UNKNOWN = 'unknown'

"""
class DatabaseType(Enum):
    NIST_NVD = "nist_nvd"
    CVELISTV5 = "cvelistV5"
"""


"""
#@ToDO: check usage!
def parse_cpe_entry(cpe_entry):
    parts = cpe_entry.split(":")
    vendor_name = parts[3]
    product_name = parts[4]
    version = parts[5]

    if vendor_name == "*":
        vendor_name = None
    return vendor_name, product_name, version
"""


class Database:
    @abstractmethod
    def connexion(slef):
        pass

    @abstractmethod
    def close(slef):
        pass

    @abstractmethod
    def update_status(self, d, product_name :str, product_version :str, package_name, vendor :str, cve_data :dict, cves_status:list, loop:list):
        pass

    @abstractmethod
    def get_cve_info(self, d, cve_data :dict):
        pass

    @staticmethod
    def cve_update(d, cve_data :dict, cve, entry :dict):
        # If no entry, just add it
        if cve not in cve_data:
            cve_data[cve] = entry
            return
        # If we are updating, there might be change in the status
        d.logger.debug(
            "Trying CVE entry update for %s from %s to %s"
            % (cve, cve_data[cve]["abbrev-status"], entry["abbrev-status"])
        )
        if cve_data[cve]["abbrev-status"] == "Unknown":
            cve_data[cve] = entry
            return
        if cve_data[cve]["abbrev-status"] == entry["abbrev-status"]:
            return
        # Update like in {'abbrev-status': 'Patched', 'status': 'version-not-in-range'} to {'abbrev-status': 'Unpatched', 'status': 'version-in-range'}
        # or {'abbrev-status': 'Patched', 'status': 'fix-file-included', 'resource': '...somecve.patch'} to {'abbrev-status': 'Unpatched', 'status': 'version-in-range'}

        if (
            entry["abbrev-status"] == "Unpatched"
            and cve_data[cve]["abbrev-status"] == "Patched"
        ):
            if (
                entry["status"] == "version-in-range"
                and cve_data[cve]["status"] == "version-not-in-range"
            ):
                # New result from the scan, vulnerable
                cve_data[cve] = entry
                d.logger.info(
                    "CVE entry %s update from Patched to Unpatched from the scan result"
                    % cve
                )
                return
            elif (
                entry["status"] == "version-in-range"
                and cve_data[cve]["status"] == "fix-file-included"
            ):
                # Issue fixed by a patch, we keep the entry
                d.logger.info(
                    "CVE entry %s vulnerable from the scan result, but have a patch" % cve
                )
                return
        # Update like in {'abbrev-status': 'Unpatched', 'status': 'version-in-range'} to  {'abbrev-status': 'Patched', 'status': 'version-not-in-range'}
        if (
            entry["abbrev-status"] == "Patched"
            and cve_data[cve]["abbrev-status"] == "Unpatched"
        ):
            if (
                entry["status"] == "version-not-in-range"
                and cve_data[cve]["status"] == "version-in-range"
            ):
                # Range does not match the scan, but we already have a vulnerable match, ignore
                d.logger.debug(
                    "CVE entry %s update from Patched to Unpatched from the scan result - not applying"
                    % cve
                )
                return

        if cve_data[cve]["abbrev-status"] == "Ignored":
            d.logger.info("CVE %s not updating because Ignored" % cve)
            return

        d.logger.warn(
            "Unsupported CVE entry update for %s from %s to %s"
            % (cve, cve_data[cve], entry)
        )