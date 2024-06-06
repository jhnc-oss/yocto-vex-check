#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import collections
import re
import itertools
import functools
import json
from cve_check_map import CVE_CHECK_STATUSMAP as cve_map
from functools import reduce

_Version = collections.namedtuple("_Version", ["release", "patch_l", "pre_l", "pre_v"])


@functools.total_ordering
class Version:

    def __init__(self, version, suffix=None):

        suffixes = ["alphabetical", "patch"]

        if str(suffix) == "alphabetical":
            version_pattern = r"""r?v?(?:(?P<release>[0-9]+(?:[-\.][0-9]+)*)(?P<patch>[-_\.]?(?P<patch_l>[a-z]))?(?P<pre>[-_\.]?(?P<pre_l>(rc|alpha|beta|pre|preview|dev))[-_\.]?(?P<pre_v>[0-9]+)?)?)(.*)?"""
        elif str(suffix) == "patch":
            version_pattern = r"""r?v?(?:(?P<release>[0-9]+(?:[-\.][0-9]+)*)(?P<patch>[-_\.]?(p|patch)(?P<patch_l>[0-9]+))?(?P<pre>[-_\.]?(?P<pre_l>(rc|alpha|beta|pre|preview|dev))[-_\.]?(?P<pre_v>[0-9]+)?)?)(.*)?"""
        else:
            version_pattern = r"""r?v?(?:(?P<release>[0-9]+(?:[-\.][0-9]+)*)(?P<pre>[-_\.]?(?P<pre_l>(rc|alpha|beta|pre|preview|dev))[-_\.]?(?P<pre_v>[0-9]+)?)?)(.*)?"""
        regex = re.compile(
            r"^\s*" + version_pattern + r"\s*$", re.VERBOSE | re.IGNORECASE
        )

        match = regex.search(version)
        if not match:
            raise Exception("Invalid version: '{0}'".format(version))

        self._version = _Version(
            release=tuple(
                int(i) for i in match.group("release").replace("-", ".").split(".")
            ),
            patch_l=(
                match.group("patch_l")
                if str(suffix) in suffixes and match.group("patch_l")
                else ""
            ),
            pre_l=match.group("pre_l"),
            pre_v=match.group("pre_v"),
        )

        self._key = _cmpkey(
            self._version.release,
            self._version.patch_l,
            self._version.pre_l,
            self._version.pre_v,
        )

    def __eq__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self._key == other._key

    def __gt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self._key > other._key


def _cmpkey(release, patch_l, pre_l, pre_v):
    # remove leading 0
    _release = tuple(
        reversed(list(itertools.dropwhile(lambda x: x == 0, reversed(release))))
    )

    _patch = patch_l.upper()

    if pre_l is None and pre_v is None:
        _pre = float("inf")
    else:
        _pre = float(pre_v) if pre_v else float("-inf")
    return _release, _patch, _pre


def get_related_vexs(d, vex_path, product, version):
    related_vexs = []
    try:
        with open(vex_path) as f:
            data = json.load(f)

            for k, v in data.items():
                vex = {}
                for statement in v["statements"]:
                    for p in statement["products"]:
                        if product == p["@id"][len("pkg:") :] or (
                            "product" in p and product == p["product"]
                        ):
                            vex[statement["vulnerability"]["name"]] = statement
                            related_vexs.append(vex)
                            d.setLayer(p["layer"])
    except Exception as e:
        d.logger.error("VEX format data unsupported: {}".format(e))

    return related_vexs


def get_patched_cves(d):
    """
    Get patches that solve CVEs using the "CVE: " tag.
    """
    patched_cves = {}
    vex_table = list(d.getVEXTable())[0]

    if len(vex_table) > 0:
        d.logger.debug(f"Scanning {len(vex_table)} patches for CVEs")

        for cve in vex_table:
            for k, v in cve.items():
                patched_cves[k] = {
                    "abbrev-status": cve_map[v["status_note"]],
                    "status": v["status_note"],
                }
                if "justification" in v.keys():
                    if v["status_note"] == "fix-file-included":
                        patched_cves[k]["resource"] = v["justification"][
                            len("Fixed by a patch file ") :
                        ]
                    else:
                        patched_cves[k]["description"] = v["justification"]

    return patched_cves


def get_cpe_ids(cve_product, version):
    """
    Get list of CPE identifiers for the given product and version
    """

    version = version.split("+git")[0]

    cpe_ids = []
    for product in cve_product.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = "*"

        cpe_id = "cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*".format(vendor, product, version)
        cpe_ids.append(cpe_id)

    return cpe_ids


def cve_check_merge_jsons(output, data):
    """
    Merge the data in the "package" property to the main data file
    output
    """
    if output["version"] != data["version"]:
        bb.error("Version mismatch when merging JSON outputs")
        return

    for product in output["package"]:
        if product["name"] == data["package"][0]["name"]:
            bb.error("Error adding the same package %s twice" % product["name"])
            return

    output["package"].append(data["package"][0])


def update_symlinks(target_path, link_path):
    """
    Update a symbolic link link_path to point to target_path.
    Remove the link and recreate it if exist and is different.
    """
    if link_path != target_path and os.path.exists(target_path):
        if os.path.exists(os.path.realpath(link_path)):
            os.remove(link_path)
        os.symlink(os.path.basename(target_path), link_path)


def convert_cve_version(version):
    """
    This function converts from CVE format to Yocto version format.
    eg 8.3_p1 -> 8.3p1, 6.2_rc1 -> 6.2-rc1

    Unless it is redefined using CVE_VERSION in the recipe,
    cve_check uses the version in the name of the recipe (${PV})
    to check vulnerabilities against a CVE in the database downloaded from NVD.

    When the version has an update, i.e.
    "p1" in OpenSSH 8.3p1,
    "-rc1" in linux kernel 6.2-rc1,
    the database stores the version as version_update (8.3_p1, 6.2_rc1).
    Therefore, we must transform this version before comparing to the
    recipe version.

    In this case, the parameter of the function is 8.3_p1.
    If the version uses the Release Candidate format, "rc",
    this function replaces the '_' by '-'.
    If the version uses the Update format, "p",
    this function removes the '_' completely.
    """

    matches = re.match("^([0-9.]+)_((p|rc)[0-9]+)$", version)

    if not matches:
        return version

    version = matches.group(1)
    update = matches.group(2)

    if matches.group(3) == "rc":
        return version + "-" + update

    return version + update


def decode_cve_status(d, cve):
    """
    Convert CVE_STATUS into status, detail and description.
    """
    status = d.getVarFlag("CVE_STATUS", cve)
    if not status:
        return ("", "", "")

    status_split = status.split(":", 1)
    detail = status_split[0]
    description = status_split[1].strip() if (len(status_split) > 1) else ""

    status_mapping = d.getVarFlag("CVE_CHECK_STATUSMAP", detail)
    if status_mapping is None:
        bb.warn(
            'Invalid detail "%s" for CVE_STATUS[%s] = "%s", fallback to Unpatched'
            % (detail, cve, status)
        )
        status_mapping = "Unpatched"

    return (status_mapping, detail, description)


def get_cpes(package_name, related_recipe, spdx_data):
    for el in spdx_data:
        for name, detail in el.items():
            if (
                "recipe_name" in detail.keys()
                and detail["recipe_name"] == related_recipe
            ):
                for p in detail["pkgs_recipe"]:
                    if p["name"] == package_name and p["cpe"] != []:
                        return p["cpe"]

    return None


def get_package_info(infos, spdx_data):
    info = []
    product_names = []

    if infos["type"] == "package":
        cpes = get_cpes(infos["pkg_name"], infos["related_recipe"], spdx_data)
        if cpes is not None:
            for cpe in cpes:
                package = {}
                full_pn = ""
                pn = ""
                # If no vendor is specified (4th in CPE), use only product name (5th in CPE)
                if cpe.split(":")[3] == "*":
                    full_pn = cpe.split(":")[4]
                    pn = full_pn
                else:
                    full_pn = ":".join(cpe.split(":")[3:5])
                    pn = cpe.split(":")[4]
                if full_pn not in product_names:
                    package["name"] = infos["pkg_name"]
                    package["product"] = full_pn
                    package["version"] = infos["pkg_version"]
                    package["cpe"] = [c for c in cpes if pn in c]
                    info.append(package)
                    product_names.append(full_pn)
        else:
            package = {}
            package["name"] = infos["pkg_name"]
            package["product"] = infos["pkg_name"]
            package["version"] = infos["pkg_version"]
            package["cpe"] = None
            info.append(package)

    elif infos["type"] == "recipe":
        for el in infos["pkgs_recipe"]:
            if el["cpe"] != []:
                for cpe in el["cpe"]:
                    full_pn = ""
                    pn = ""
                    # If no vendor is specified (4th in CPE), use only product name (5th in CPE)
                    if cpe.split(":")[3] == "*":
                        full_pn = cpe.split(":")[4]
                        pn = full_pn
                    else:
                        full_pn = ":".join(cpe.split(":")[3:5])
                        pn = cpe.split(":")[4]
                    if full_pn not in product_names:
                        package = {}
                        package["name"] = el["name"]
                        package["product"] = full_pn
                        package["version"] = el["version"]
                        package["cpe"] = [c for c in el["cpe"] if pn in c]
                        info.append(package)
                        product_names.append(full_pn)
            else:
                package = {}
                package["name"] = el["name"]
                package["product"] = el["name"]
                package["version"] = el["version"]
                package["cpe"] = None
                info.append(package)

    # Multiple product names case (eg. curl / libcurl),
    # for the same package name and version
    if (
        len(info) > 1
        and len(list(set([el["name"] for el in info]))) == 1
        and len(list(set([el["version"] for el in info]))) == 1
    ):

        tmp = [
            {
                "name": info[0]["name"],
                "product": " ".join(list(set([el["product"] for el in info]))),
                "version": info[0]["version"],
                "cpe": list(
                    set(reduce(lambda a, b: a + b, [el["cpe"] for el in info]))
                ),
            }
        ]
        info = tmp

    return info
