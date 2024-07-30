#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
from abc import abstractmethod
import os
import sqlite3
import json
import re
from cve_check_lib import (
    Version,
    convert_cve_version,
    decode_cve_status,
    get_related_vexs,
)


def cve_is_status(d, cve_data, cve, status):
    if cve not in cve_data:
        return False
    if "abbrev-status" not in cve_data[cve]:
        return False
    if cve_data[cve]["abbrev-status"] == status:
        return True
    return False


def cve_is_ignored(d, cve_data, cve):
    return cve_is_status(d, cve_data, cve, "Ignored")


def cve_is_patched(d, cve_data, cve):
    return cve_is_status(d, cve_data, cve, "Patched")


def cve_update(d, cve_data, cve, entry):
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


def parse_cve_id(cve):
    pattern = pattern = r"CVE-(\d{4})-(\d+)\.json"
    match = re.match(pattern, cve)
    if match:
        year = match.group(1)
        number = match.group(2)
        return year, number
    else:
        return None, None


def is_semver(version):
    semver_pattern = r"^\d+(\.\d+){0,2}$"

    if version == "unspecified":
        return True
    if version == "0":
        return True
    if re.match(semver_pattern, version):
        return True
    return False


# Process a parsed (split) semver. Add zeros if the version has
# less than three digits
def normalize_semver(version):
    if len(version) == 1:
        version.append(0)
    if len(version) == 2:
        version.append(0)


def is_supported_custom(version):
    semver_pattern = r"^\d+(\.\d+){0,2}$"
    openssl_pattern = r"^\d+(\.\d+)*[a-z]*(-dev)?$"

    if re.match(semver_pattern, version):
        return True
    if re.match(openssl_pattern, version):
        return True

    return False


def match_custom_equal(version, target_version):
    semver_pattern = r"^\d+(\.\d+){0,2}$"
    openssl_pattern = r"^\d+(\.\d+)*[a-z]*(-dev)?$"

    if re.match(semver_pattern, version) and re.match(semver_pattern, target_version):
        return match_semver_equal(version, target_version)
    elif re.match(openssl_pattern, version) and re.match(
        openssl_pattern, target_version
    ):
        v = compute_openssl_version(version)
        t = compute_openssl_version(target_version)
        return v == t

    return False


def match_semver_equal(version, target_version):
    version_parts = version.split(".")
    target_parts = target_version.split(".")

    # Add missing zeros if needed
    normalize_semver(version_parts)
    normalize_semver(target_parts)

    # Compare all digits
    if (
        int(version_parts[0]) == int(target_parts[0])
        and int(version_parts[1]) == int(target_parts[1])
        and int(version_parts[2]) == int(target_parts[2])
    ):
        return True
    else:
        return False


def compute_openssl_version(version):
    if version == "*":
        return tuple([tuple([0, 0, 0]), tuple([0]), 0])

    version_parts = version.split(".")
    digits = []
    letters = []
    dev_version = 1

    # Compute Major and minors
    for i in range(0, len(version_parts) - 1):
        digits.append(int(version_parts[i]))

    # Filter letters and "-dev" from last digit
    subparts = list(filter(len, re.split("(\d+)", version_parts[-1])))
    digits.append(int(subparts[0]))
    if len(subparts) > 1:
        if "-dev" in subparts[1]:
            dev_version = 0
            subparts[1] = subparts[1][:-4]
        for char in subparts[1]:
            letters.append(ord(char))

    while len(digits) <= 2:
        digits.append(0)

    return tuple([tuple(digits), tuple(letters), dev_version])


def match_custom_less_equal(version, target_version):
    semver_pattern = r"^\d+(\.\d+){0,2}$"
    openssl_pattern = r"^\d+(\.\d+)*[a-z]*(-dev)?$"

    if (re.match(semver_pattern, version)) and (
        re.match(semver_pattern, target_version)
    ):
        return match_semver_less_equal(version, target_version)
    elif re.match(openssl_pattern, version) and re.match(
        openssl_pattern, target_version
    ):
        if match_custom_equal(version, target_version):
            return True
        else:
            return match_custom_less(version, target_version)

    return False


def match_custom_less(version, target_version):
    semver_pattern = r"^\d+(\.\d+){0,2}$"
    openssl_pattern = r"^\d+(\.\d+)*[a-z]*(-dev)?$"

    if (re.match(semver_pattern, version)) and (
        re.match(semver_pattern, target_version)
    ):
        return match_semver_less(version, target_version)
    elif re.match(openssl_pattern, version) and re.match(
        openssl_pattern, target_version
    ):
        v = compute_openssl_version(version)
        t = compute_openssl_version(target_version)
        return t < v

    return False


def match_custom_greater(version, target_version):
    semver_pattern = r"^\d+(\.\d+){0,2}$"
    openssl_pattern = r"^\d+(\.\d+)*[a-z]*(-dev)?$"

    if (re.match(semver_pattern, version)) and (
        re.match(semver_pattern, target_version)
    ):
        return match_semver_greater(version, target_version)
    elif (re.match(openssl_pattern, version)) and (
        re.match(openssl_pattern, target_version)
    ):
        v = compute_openssl_version(version)
        t = compute_openssl_version(target_version)
        return t > v

    return False


def match_semver_less_equal(version, target_version):

    if match_semver_less(version, target_version) == True:
        return True

    if match_semver_equal(version, target_version) == True:
        return True

    return False


def match_semver_less(version, target_version):
    version_pattern = r"^\d+(\.\d+){0,2}$"

    if not (re.match(version_pattern, version)):
        return False
    if not (re.match(version_pattern, target_version)):
        return False

    version_parts = version.split(".")
    target_parts = target_version.split(".")

    # Add missing zeros if needed
    normalize_semver(version_parts)
    normalize_semver(target_parts)

    if int(version_parts[0]) > int(target_parts[0]):
        return True

    if int(version_parts[0]) < int(target_parts[0]):
        return False

    if int(version_parts[1]) > int(target_parts[1]):
        return True

    if int(version_parts[1]) < int(target_parts[1]):
        return False

    if int(version_parts[2]) > int(target_parts[2]):
        return True

    return False


def match_semver_greater(version, target_version):
    version_pattern = r"^\d+(\.\d+){0,2}$"

    if not (re.match(version_pattern, version)):
        return False
    if not (re.match(version_pattern, target_version)):
        return False

    version_parts = version.split(".")
    target_parts = target_version.split(".")

    # Add missing zeros if needed
    normalize_semver(version_parts)
    normalize_semver(target_parts)

    # Compare major and minor versions
    if int(version_parts[0]) < int(target_parts[0]):
        return True

    if int(version_parts[0]) > int(target_parts[0]):
        return False

    if int(version_parts[1]) < int(target_parts[1]):
        return True

    if int(version_parts[1]) > int(target_parts[1]):
        return False

    if int(version_parts[2]) < int(target_parts[2]):
        return True

    return False


def parse_cpe_entry(cpe_entry):
    parts = cpe_entry.split(":")
    vendor_name = parts[3]
    product_name = parts[4]
    version = parts[5]

    if vendor_name == "*":
        vendor_name = None
    return vendor_name, product_name, version


class Database:
    @abstractmethod
    def connexion():
        pass

    @abstractmethod
    def close():
        pass

    @abstractmethod
    def update_status(self, d, product, pv, pn, vendor, cve_data, cves_status):
        pass


class NVDDatabase(Database):
    def __init__(self, path):
        self.path = path

    def connexion(self):
        if os.path.exists(self.path):
            db_file = "file:" + self.path + "?mode=ro"
            self.conn = sqlite3.connect(db_file, uri=True)
            return self.conn
        else:
            return None

    def update_status(self, d, product, pv, pn, vendor, cve_data, cves_status):
        # Find all relevant CVE IDs.
        has_cves_in_product = False
        real_pv = d.getVar("PV")
        suffix = d.getVar("CVE_VERSION_SUFFIX")

        cve_cursor = self.conn.execute(
            "SELECT DISTINCT ID FROM PRODUCTS WHERE PRODUCT IS ? AND VENDOR LIKE ?",
            (product, vendor),
        )
        for cverow in cve_cursor:
            cve = cverow[0]

            if cve_is_ignored(d, cve_data, cve):
                d.logger.debug("%s-%s ignores %s" % (product, pv, cve))
                continue
            elif cve_is_patched(d, cve_data, cve):
                d.logger.debug("%s has been patched" % (cve))
                continue
            # Write status once only for each product
            if has_cves_in_product:
                cves_status.append([product, True])

            vulnerable = False
            ignored = False

            product_cursor = self.conn.execute(
                "SELECT * FROM PRODUCTS WHERE ID IS ? AND PRODUCT IS ? AND VENDOR LIKE ?",
                (cve, product, vendor),
            )
            for row in product_cursor:
                (_, _, _, version_start, operator_start, version_end, operator_end) = (
                    row
                )
                if cve_is_ignored(d, cve_data, cve):
                    ignored = True

                version_start = convert_cve_version(version_start)
                version_end = convert_cve_version(version_end)

                if (
                    operator_start == "=" and pv == version_start
                ) or version_start == "-":
                    vulnerable = True
                else:
                    if operator_start:
                        try:
                            vulnerable_start = operator_start == ">=" and Version(
                                pv, suffix
                            ) >= Version(version_start, suffix)
                            vulnerable_start |= operator_start == ">" and Version(
                                pv, suffix
                            ) > Version(version_start, suffix)
                        except:
                            d.logger.warn(
                                "%s: Failed to compare %s %s %s for %s"
                                % (product, pv, operator_start, version_start, cve)
                            )
                            vulnerable_start = False
                    else:
                        vulnerable_start = False

                    if operator_end:
                        try:
                            vulnerable_end = operator_end == "<=" and Version(
                                pv, suffix
                            ) <= Version(version_end, suffix)
                            vulnerable_end |= operator_end == "<" and Version(
                                pv, suffix
                            ) < Version(version_end, suffix)
                        except:
                            d.logger.warn(
                                "%s: Failed to compare %s %s %s for %s"
                                % (product, pv, operator_end, version_end, cve)
                            )
                            vulnerable_end = False
                    else:
                        vulnerable_end = False

                    if operator_start and operator_end:
                        vulnerable = vulnerable_start and vulnerable_end
                    else:
                        vulnerable = vulnerable_start or vulnerable_end

                if vulnerable:
                    if ignored:
                        d.logger.debug("%s is ignored in %s-%s" % (cve, pn, real_pv))
                        cve_update(d, cve_data, cve, {"abbrev-status": "Ignored"})
                    else:
                        d.logger.debug("%s-%s is vulnerable to %s" % (pn, real_pv, cve))
                        cve_update(
                            d,
                            cve_data,
                            cve,
                            {
                                "abbrev-status": "Unpatched",
                                "status": "version-in-range",
                            },
                        )
                    break
            product_cursor.close()

            if not vulnerable:
                d.logger.debug("%s-%s is not vulnerable to %s" % (pn, real_pv, cve))
                cve_update(
                    d,
                    cve_data,
                    cve,
                    {"abbrev-status": "Patched", "status": "version-not-in-range"},
                )
        cve_cursor.close()

    def get_cve_info(self, cve_data):
        for cve in cve_data:
            cursor = self.conn.execute("SELECT * FROM NVD WHERE ID IS ?", (cve,))
            for row in cursor:
                # The CVE itself has been added already
                if row[0] not in cve_data:
                    d.logger.info("CVE record %s not present" % row[0])
                    continue

                cve_data[row[0]]["NVD-summary"] = row[1]
                cve_data[row[0]]["NVD-scorev2"] = row[2]
                cve_data[row[0]]["NVD-scorev3"] = row[3]
                cve_data[row[0]]["NVD-modified"] = row[4]
                cve_data[row[0]]["NVD-vector"] = row[5]
                cve_data[row[0]]["NVD-vectorString"] = row[6]
            cursor.close()

    def close(self):
        self.conn.close()


class CVEDatabase(Database):
    def __init__(self, path):
        self.path = path
        self.cves = {}
        products = []
        for root, dirnames, filenames in os.walk(self.path):
            for filename in filenames:
                year, number = parse_cve_id(filename)
                if filename.endswith(".json") and year is not None:
                    with open(os.path.join(root, filename)) as f:
                        cve_id = "CVE-" + year + "-" + number
                        data = json.load(f)
                        try:
                            if "containers" in data:
                                if "adp" in data["containers"]:
                                    for adp in data["containers"]["adp"]:
                                        if "affected" in adp:
                                            for x in adp["affected"]:
                                                products.append(
                                                    (x["product"], x, data, cve_id)
                                                )
                                elif "cna" in data["containers"]:
                                    if "affected" in data["containers"]["cna"]:
                                        for x in data["containers"]["cna"]["affected"]:
                                            products.append(
                                                (x["product"], x, data, cve_id)
                                            )
                            self.cves[cve_id] = data

                        except KeyError:
                            pass
                        except TypeError:
                            pass
        self.products_sorted = sorted(products, key=lambda product: product[0])

    def connexion(self):
        return self.products_sorted

    def is_affected(self, d, cve, entries, version):
        # Remove the '+git' suffix
        version = version.split("+git")[0]

        # Filter out unsupported version
        if not is_supported_custom(version):
            return "unknown"

        if "versions" not in entries:
            if "defaultStatus" in entries:
                if entries["defaultStatus"] == "affected":
                    return "affected"
                elif entries["defaultStatus"] == "unaffected":
                    return "not affected"
            return "unknown"

        for entry in entries["versions"]:
            # Filter out "git" entries that we do not support yet (they have hashes)
            if "versionType" in entry and entry["versionType"] == "git":
                continue

            # Check if custom version is currently supported
            if "versionType" in entry and entry["versionType"] == "custom":
                if not is_supported_custom(entry["version"]):
                    continue
                if (
                    "lessThan" in entry and not is_supported_custom(entry["lessThan"])
                ) or (
                    "lessThanOrEqual" in entry
                    and not is_supported_custom(entry["lessThanOrEqual"])
                ):
                    continue

            if "version" not in entry:
                d.logger.info("Entry without version... skipping " + str(entry))
                return "unknown"

            # Entries like  'versions': [{'status': 'affected', 'version': '3.5.12'}]}
            if (entry["status"] == "affected") and "versionType" not in entry:
                if entry["version"] == version:
                    return "affected"
                # If has only one version, but doesn't match ours, try another entry
                if is_semver(entry["version"]):
                    continue
                # Malformed/unsupported type of version
                d.logger.info("Malformed entry... skipping " + str(entry))
                return "unknown"

            # Malformed/unsupported version, skip parsing
            if (entry["status"] == "affected") and not is_semver(entry["version"]):
                d.logger.info("Malformed entry... skipping " + str(entry))
                return "unknown"

            if entry["status"] == "affected" and entry["versionType"] == "semver":
                if "lessThanOrEqual" in entry:
                    if match_semver_less_equal(
                        entry["lessThanOrEqual"], version
                    ) and match_semver_greater(entry["version"], version):
                        return "affected"
                elif "lessThan" in entry:
                    if match_semver_less(
                        entry["lessThan"], version
                    ) and match_semver_greater(entry["version"], version):
                        return "affected"
                elif match_semver_equal(entry["version"], version):
                    return "affected"
            elif entry["status"] == "affected" and entry["versionType"] == "custom":
                if match_custom_equal(entry["version"], version):
                    return "affected"
                elif "lessThanOrEqual" in entry:
                    if match_custom_less_equal(
                        entry["lessThanOrEqual"], version
                    ) and match_custom_greater(entry["version"], version):
                        return "affected"
                elif "lessThan" in entry:
                    if match_custom_less(
                        entry["lessThan"], version
                    ) and match_custom_greater(entry["version"], version):
                        return "affected"

        return "not affected"

    def update_status(self, d, product, version, pn, vendor, cve_data, cves_status, loop):
        if vendor == "%":
            vendor = "*"

        # Store vendor-product pair to avoid infinite loop
        loop.append(f"{vendor}-{product}")
        loop = list(set(loop))

        for pr in self.products_sorted:
            if pr[0].lower() == product and (
                (vendor == "*") or (vendor.lower() == pr[1]["vendor"].lower())
            ):
                cve = pr[3]
                vuln_status = self.is_affected(d, cve, pr[1], version)
                if vuln_status == "affected":
                    cve_update(
                        d,
                        cve_data,
                        cve,
                        {"abbrev-status": "Unpatched", "status": "version-in-range"},
                    )
                    print(pr[3] + ": affected: " + product + " " + version)
                elif vuln_status == "unknown":
                    print(pr[3] + ": unknown status: " + product + " " + version)
                    cve_update(d, cve_data, cve, {"abbrev-status": "Unknown"})
                elif vuln_status == "not affected":
                    print(pr[3] + ": not affected " + product + " " + version)
                    cve_update(
                        d,
                        cve_data,
                        cve,
                        {"abbrev-status": "Patched", "status": "version-not-in-range"},
                    )
                
                if "cpes" in pr[1].keys():
                    for cpe in pr[1]["cpes"]:
                        cpe_vendor = cpe.split(":")[3]
                        cpe_product = cpe.split(":")[4]
                        if f"{cpe_vendor}-{cpe_product}" not in loop:
                            if cpe_vendor.lower() != vendor.lower() or cpe_product != product:
                                self.update_status(d, cpe_product, version, pn, cpe_vendor, cve_data, cves_status, loop)

    def get_cve_info(self, cve_data):
        for cve in cve_data:
            if cve not in self.cves:
                print("ERRROR: no entry for " + cve)
                continue
            entry = self.cves[cve]
            if "containers" in entry:
                if "cna" in entry["containers"]:
                    # Search for 'title' as summary. If it does not exists, go to 'description'
                    if "title" in entry["containers"]["cna"]:
                        cve_data[cve]["CVE-summary"] = entry["containers"]["cna"][
                            "title"
                        ]
                    elif "descriptions" in entry["containers"]["cna"]:
                        for d in entry["containers"]["cna"]["descriptions"]:
                            if d["lang"] == "en":
                                cve_data[cve]["CVE-summary"] = d["value"]
                    # Only CVSS 3.1 in practice for now
                    if "metrics" in entry["containers"]["cna"]:
                        for m in entry["containers"]["cna"]["metrics"]:
                            if "cvssV3_1" in m:
                                cve_data[cve]["CVE-scorev31"] = m["cvssV3_1"][
                                    "baseScore"
                                ]
                                cve_data[cve]["CVE-vectorString"] = m["cvssV3_1"][
                                    "vectorString"
                                ]
                if "adp" in entry["containers"]:
                    cve_data[cve]["adp-title"] = entry["containers"]["adp"][0]["title"]
                    for adp in entry["containers"]["adp"]:
                        if "metrics" in adp:
                            for m in adp["metrics"]:
                                for k, v in m.items():
                                    if k == "cvssV3_1":
                                        cve_data[cve]["CVE-scorev31"] = v["baseScore"]
                                        cve_data[cve]["CVE-vectorString"] = v[
                                            "vectorString"
                                        ]
                                    if k == "other" and v["type"] == "ssvc":
                                        cve_data[cve]["CVE-ssvc"] = v["content"][
                                            "options"
                                        ]
                        if "affected" in adp:
                            for x in adp["affected"]:
                                if "cpes" in x:
                                    cve_data[cve]["cpes"] = x["cpes"]
            if "cveMetadata" in cve:
                cve_data[cve]["CVE-modified"] = cve["cveMetadata"]["dateUpdated"]
        return cve_data

    def close(self):
        pass
