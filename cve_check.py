#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

# This class is used to check recipes against public CVEs.
#
# In order to use this class just inherit the class in the
# local.conf file and it will add the cve_check task for
# every recipe. The task can be used per recipe, per image,
# or using the special cases "world" and "universe". The
# cve_check task will print a warning for every unpatched
# CVE found and generate a file in the recipe WORKDIR/cve
# directory. If an image is build it will generate a report
# in DEPLOY_DIR_IMAGE for all the packages used.
#
# Example:
#   bitbake -c cve_check openssl
#   bitbake core-image-sato
#   bitbake -k -c cve_check universe
#
# DISCLAIMER
#
# This class/tool is meant to be used as support and not
# the only method to check against CVEs. Running this tool
# doesn't guarantee your packages are free of CVEs.

import logging
import shutil
import time
import os
import json
from logging import Logger

from cve_check_lib import update_symlinks
from cve_check_lib import get_patched_cves
from cve_check_lib import cve_check_merge_jsons
from cve_check_lib import (
    Version,
    convert_cve_version,
    decode_cve_status,
    get_related_vexs,
)
from cve_check_lib import (
    get_package_info_spdx,
    get_package_info_cve,
)
from nvd_database import NVDDatabase
from cve_database import CVEDatabase
#from databases import NVDDatabase, CVEDatabase
from cve_check_map import CVE_CHECK_STATUSMAP as cve_map
import datetime


class CheckerConfig:

    # The product name that the CVE database uses defaults to BPN, but may need to
    # be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
    CVE_PRODUCT = "linux_kernel"
    CVE_VERSION = "6.4.0"
    CVE_PACKAGE = "linux-yocto"

    CVE_CHECK_DB_DIR = "/tmp/download/CVE_CHECK"
    CVE_CHECK_DB_FILE = "build/downloads/CVE_CHECK/nvdcve_2-1.db"
    CVE_CHECK_DB_FILE_LOCK = "/tmp/nvdcve_2-1.lock"
    T = "target"

    CVE_CHECK_LOG = "target" + "/cve.log"
    CVE_CHECK_TMP_FILE = "cve_check"
    CVE_CHECK_SUMMARY_DIR = "/tmp/log/cve"
    CVE_CHECK_SUMMARY_FILE_NAME = "cve-summary"
    CVE_CHECK_SUMMARY_FILE_NAME_JSON = "cve-summary.json"
    CVE_CHECK_SUMMARY_INDEX_PATH = "cve/log/cve-summary-index.txt"
    CVE_CHECK_LOG_JSON_DIR = "cve/log"

    CVE_CHECK_LOG_JSON = "/tmp/cve.json"
    CVE_CHECK_SUMMARY_JSON = "cve-summary.json"

    CVE_CHECK_DIR = "${DEPLOY_DIR}/cve"
    CVE_CHECK_RECIPE_FILE = "${CVE_CHECK_DIR}/${PN}"
    CVE_CHECK_RECIPE_FILE_JSON = "/tmp/result_cve.json"
    CVE_CHECK_MANIFEST = "${IMGDEPLOYDIR}/${IMAGE_NAME}.cve"
    CVE_CHECK_MANIFEST_JSON = "/tmp/image.json"
    CVE_CHECK_COPY_FILES = "1"
    CVE_CHECK_CREATE_MANIFEST = "1"

    # Report Patched or Ignored CVEs
    CVE_CHECK_REPORT_PATCHED = "1"

    CVE_CHECK_SHOW_WARNINGS = "1"

    # Provide text output
    CVE_CHECK_FORMAT_TEXT = "0"

    # Provide JSON output
    CVE_CHECK_FORMAT_JSON = "1"

    # Check for packages without CVEs (no issues or missing product name)
    CVE_CHECK_COVERAGE = "1"

    # Skip CVE Check for packages (PN)
    CVE_CHECK_SKIP_RECIPE = ""

    # Replace NVD DB check status for a given CVE. Each of CVE has to be mentioned
    # separately with optional detail and description for this status.
    #
    # CVE_STATUS[CVE-1234-0001] = "not-applicable-platform: Issue only applies on Windows"
    # CVE_STATUS[CVE-1234-0002] = "fixed-version: Fixed externally"
    #
    # Settings the same status and reason for multiple CVEs is possible
    # via CVE_STATUS_GROUPS variable.
    #
    # CVE_STATUS_GROUPS = "CVE_STATUS_WIN CVE_STATUS_PATCHED"
    #
    # CVE_STATUS_WIN = "CVE-1234-0001 CVE-1234-0003"
    # CVE_STATUS_WIN[status] = "not-applicable-platform: Issue only applies on Windows"
    # CVE_STATUS_PATCHED = "CVE-1234-0002 CVE-1234-0004"
    # CVE_STATUS_PATCHED[status] = "fixed-version: Fixed externally"
    #
    # All possible CVE statuses could be found in cve-check-map.conf
    # CVE_CHECK_STATUSMAP[not-applicable-platform] = "Ignored"
    # CVE_CHECK_STATUSMAP[fixed-version] = "Patched"
    #
    # CVE_CHECK_IGNORE is deprecated and CVE_STATUS has to be used instead.
    # Keep CVE_CHECK_IGNORE until other layers migrate to new variables
    CVE_CHECK_IGNORE = ""

    # Layers to be excluded
    CVE_CHECK_LAYER_EXCLUDELIST = ""

    # Layers to be included
    CVE_CHECK_LAYER_INCLUDELIST = ""

    # set to "alphabetical" for version using single alphabetical character as increment release
    CVE_VERSION_SUFFIX = ""

    logger = ""
    BASE_PATH = "data"
    RECIPE_PATH = "cve/recipe/"
    CPE_table = None
    # Which database to use
    DB = "NVD"
    LAYER_PATH = None
    LAYER = "meta"
    ALL_RECIPES_PATH = None
    RECIPE = None
    PATCH_FILES = None
    CVE_STATUS = {}
    CVE_CHECK_STATUSMAP = cve_map
    VEX_table = None
    SPDX_SUMMARY_PATH = None
    FORMER_CVE_SUMMARY_PATH = None

    def getVar(self, variable):
        if variable == "CVE_CHECK_IGNORE":
            return self.CVE_CHECK_IGNORE
        elif variable == "CVE_CHECK_DB_FILE":
            return os.path.join(os.getcwd(), self.CVE_CHECK_DB_FILE)
        elif variable == "CVE_PRODUCT":
            return self.CVE_PRODUCT
        elif variable == "CVE_VERSION":
            return self.CVE_VERSION
        elif variable == "CVE_PACKAGE":
            return self.CVE_PACKAGE
        elif variable == "CVE_CHECK_SKIP_RECIPE":
            return "0"
        elif variable == "CVE_CHECK_COVERAGE":
            return self.CVE_CHECK_COVERAGE
        elif variable == "CVE_CHECK_FORMAT_TEXT":
            return self.CVE_CHECK_FORMAT_TEXT
        elif variable == "CVE_CHECK_FORMAT_JSON":
            return self.CVE_CHECK_FORMAT_JSON
        elif variable == "CVE_CHECK_LAYER_INCLUDELIST":
            return self.CVE_CHECK_LAYER_INCLUDELIST
        elif variable == "CVE_CHECK_LAYER_EXCLUDELIST":
            return self.CVE_CHECK_LAYER_EXCLUDELIST
        elif variable == "CVE_CHECK_LOG_JSON":
            product = self.CVE_PRODUCT

            # CVE_PRODUCT may contain multiple product names separated by spaces.
            # It can also contain part of CPE, such as the vendor:product pair.
            # CVE_CHECK_LOG_JSON then returns cve log filename containing only product names.
            if len(self.CVE_PRODUCT.split()) > 1:
                product = "-".join(
                    list(
                        set(
                            [
                                p.split(":")[1]
                                for p in self.CVE_PRODUCT.split()
                                if ":" in p
                            ]
                            + [p for p in self.CVE_PRODUCT.split() if ":" not in p]
                        )
                    )
                )

            return os.path.join(
                os.getcwd(),
                self.BASE_PATH,
                self.CVE_CHECK_LOG_JSON_DIR,
                "log-" + product + "-" + self.CVE_VERSION + ".cve.json",
            )
        elif variable == "CVE_CHECK_RECIPE_FILE_JSON":
            return os.path.join(
                os.getcwd(),
                self.BASE_PATH,
                self.RECIPE_PATH,
                "recipe-" + self.CVE_PRODUCT + "-" + self.CVE_VERSION + ".cve.json",
            )
        elif variable == "CVE_CHECK_SUMMARY_FILE_NAME_JSON":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, self.CVE_CHECK_SUMMARY_FILE_NAME_JSON
            )
        elif variable == "CVE_CHECK_SUMMARY_FILE_NAME":
            return self.CVE_CHECK_SUMMARY_FILE_NAME
        elif variable == "CVE_CHECK_REPORT_PATCHED":
            return self.CVE_CHECK_REPORT_PATCHED
        elif variable == "CVE_CHECK_SUMMARY_DIR":
            return os.path.join(os.getcwd(), self.BASE_PATH)
        elif variable == "CVE_CHECK_LOG_JSON_DIR":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, self.CVE_CHECK_LOG_JSON_DIR
            )
        elif variable == "CVE_CHECK_TMP_FILE":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, "cve", self.CVE_CHECK_TMP_FILE
            )
        elif variable == "CVE_CHECK_SUMMARY_INDEX_PATH":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, self.CVE_CHECK_SUMMARY_INDEX_PATH
            )
        elif variable == "CVE_CHECK_SUMMARY_JSON":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, self.CVE_CHECK_SUMMARY_JSON
            )
        elif variable == "PN":
            return self.CVE_PACKAGE
        elif variable == "PP":
            return self.CVE_PRODUCT
        elif variable == "PV":
            return self.CVE_VERSION
        elif variable == "EXTENDPE":
            return ""
        elif variable == "BASE_PATH":
            return self.BASE_PATH
        elif variable == "CPE_table":
            return self.CPE_table
        elif variable == "CVE_CHECK_STATUSMAP":
            return self.CVE_CHECK_STATUSMAP
        else:
            return None

    def getVarFlag(self, variable, flag):
        self.logger.debug("getVarFlag not implemented")
        return None

    def getVarFlags(self, variable):
        self.logger.debug("getVarFlags not implemented")
        return None

    def setVarFlag(self, variable, flag):
        self.logger.debug("setVarFlag not implemented")

    def getLayer(self):
        return self.LAYER

    def setLayer(self, layer):
        self.LAYER = layer

    def resetLayer(self):
        self.LAYER = "meta"

    def setPN(self, name):
        self.CVE_PACKAGE = name

    def setPV(self, version):
        self.CVE_VERSION = version

    def resetPN(self):
        self.CVE_PACKAGE = "linux-yocto"

    def setProduct(self, name):
        self.CVE_PRODUCT = name

    def resetProduct(self):
        self.CVE_PRODUCT = "linux_kernel"

    def resetPV(self):
        self.CVE_VERSION = "6.1.0"

    def setLogger(self, log):
        self.logger = log

    def setCPETable(self, *cpe):
        self.CPE_table = cpe

    def getCPETable(self):
        return self.CPE_table

    def resetCPETable(self):
        self.CPE_table = None

    def setVEXTable(self, *vexs):
        self.VEX_table = vexs

    def resetVEXTable(self):
        self.VEX_table = None

    def getVEXTable(self):
        return self.VEX_table

    def setVEXPath(self, path):
        self.VEX_SUMMARY_PATH = path

    def getVEXPath(self):
        return self.VEX_SUMMARY_PATH

    def setSPDXPath(self, path):
        self.SPDX_SUMMARY_PATH = path

    def getSPDXPath(self):
        return self.SPDX_SUMMARY_PATH

    def setCVEPath(self, path):
        self.FORMER_CVE_SUMMARY_PATH = path

    def getCVEPath(self):
        return self.FORMER_CVE_SUMMARY_PATH

    def getDefaultDatabase(self):
        db_file = self.getVar("CVE_CHECK_DB_FILE")
        if self.DB == "NVD":
            return self.getNVDDatabase(db_file)
        if self.DB == "CVE":
            return self.getCVEDatabase(db_file)

    def setDatabaseType(self, db_type):
        if db_type == "NVD":
            self.DB = "NVD"
        elif db_type == "CVE":
            self.DB = "CVE"

    def getDatabase(self, path):
        self.setDBPath(path)
        if self.DB == "NVD":
            return self.getNVDDatabase(path)
        if self.DB == "CVE":
            return self.getCVEDatabase(path)

    def setDBPath(self, path):
        self.CVE_CHECK_DB_FILE = path

    def getNVDDatabase(self, path):
        self.database = NVDDatabase(path)
        return self.database

    def getCVEDatabase(self, path):
        self.database = CVEDatabase(path)
        return self.database

    def getDatabaseConnection(self):
        conn = self.database.connexion()
        if conn is not None:
            return self.database
        else:
            d.logger.error("Path to db not found")


def check_ignore(d):
    # Fallback all CVEs from CVE_CHECK_IGNORE to CVE_STATUS
    cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
    if cve_check_ignore:
        bb.warn("CVE_CHECK_IGNORE is deprecated in favor of CVE_STATUS")
        for cve in (d.getVar("CVE_CHECK_IGNORE") or "").split():
            d.setVarFlag("CVE_STATUS", cve, "ignored")

    # Process CVE_STATUS_GROUPS to set multiple statuses and optional detail or description at once
    for cve_status_group in (d.getVar("CVE_STATUS_GROUPS") or "").split():
        cve_group = d.getVar(cve_status_group)
        if cve_group is not None:
            for cve in cve_group.split():
                d.setVarFlag(
                    "CVE_STATUS", cve, d.getVarFlags(cve_status_group, "status")
                )
        else:
            d.logger.warning(
                "CVE_STATUS_GROUPS contains undefined variable %s" % cve_status_group
            )


def generate_json_report(d, out_path, link_path):
    # Gather cves (JSON format)
    data_summary = {}
    with open(out_path) as sumf:
        try:
            data_summary = json.load(sumf)
        except Exception as e:
            print(e)
        if not data_summary:
            data_summary = {"version": "1", "package": []}

    with open(link_path) as f:
        data = json.load(f)

        if data["package"][0]["issue"]:
            data_summary["package"].append(data["package"][0])

    with open(out_path, "w") as fa:
        json.dump(data_summary, fa, indent=2)


def cve_save_summary_handler(d):

    cve_summary_name = d.getVar("CVE_CHECK_SUMMARY_FILE_NAME_JSON")
    cvelogpath = d.getVar("CVE_CHECK_LOG_JSON_DIR")

    data_summary = {"version": "1", "package": []}

    if os.path.exists(cvelogpath):
        if d.getVar("CVE_CHECK_FORMAT_JSON") == "1":
            for el in os.listdir(cvelogpath):
                _, file_extension = os.path.splitext(el)
                if file_extension != '.json':
                    continue
                with open(os.path.join(cvelogpath, el)) as f:
                    data = json.load(f)

                    if data["package"][0]["issue"]:
                        data_summary["package"].append(data["package"][0])

            with open(cve_summary_name, "w") as fa:
                json.dump(data_summary, fa, indent=2)
            d.logger.info(
                "Complete CVE JSON report summary created at: %s" % cve_summary_name
            )
    else:
        d.logger.error("No CVE log found")


def do_cve_check(d):
    """
    Check recipe for patched and unpatched CVEs
    """
    if os.path.exists(d.getVar("CVE_CHECK_DB_FILE")):
        try:
            patched_cves = get_patched_cves(d)
        except FileNotFoundError:
            d.logger.error("Failure in searching patches")

        cve_data, status = check_cves(d, patched_cves)
        if len(cve_data) or (d.getVar("CVE_CHECK_COVERAGE") == "1" and status):
            get_cve_info(d, cve_data)
            cve_write_data(d, cve_data, status)
    else:
        d.logger.error("No CVE database found, skipping CVE check")


def cve_check_cleanup():
    """
    Delete the file used to gather all the CVE information.
    """
    bb.utils.remove(e.data.getVar("CVE_CHECK_TMP_FILE"))
    bb.utils.remove(e.data.getVar("CVE_CHECK_SUMMARY_INDEX_PATH"))


def cve_check_write_rootfs_manifest(d):
    """
    Create CVE manifest when building an image
    """
    from oe.rootfs import image_list_installed_packages

    if d.getVar("CVE_CHECK_COPY_FILES") == "1":
        deploy_file = d.getVar("CVE_CHECK_RECIPE_FILE")
        if os.path.exists(deploy_file):
            bb.utils.remove(deploy_file)
        deploy_file_json = d.getVar("CVE_CHECK_RECIPE_FILE_JSON")
        if os.path.exists(deploy_file_json):
            bb.utils.remove(deploy_file_json)

    # Create a list of relevant recipies
    recipies = set()
    for pkg in list(image_list_installed_packages(d)):
        pkg_info = os.path.join(d.getVar("PKGDATA_DIR"), "runtime-reverse", pkg)
        pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
        recipies.add(pkg_data["PN"])

    d.logger.info("Writing rootfs CVE manifest")
    deploy_dir = d.getVar("IMGDEPLOYDIR")
    link_name = d.getVar("IMAGE_LINK_NAME")

    json_data = {"version": "1", "package": []}
    text_data = ""
    enable_json = d.getVar("CVE_CHECK_FORMAT_JSON") == "1"
    enable_text = d.getVar("CVE_CHECK_FORMAT_TEXT") == "1"

    save_pn = d.getVar("PP")

    for pkg in recipies:
        # To be able to use the CVE_CHECK_RECIPE_FILE variable we have to evaluate
        # it with the different PN names set each time.
        d.setVar("PN", pkg)
        if enable_text:
            pkgfilepath = d.getVar("CVE_CHECK_RECIPE_FILE")
            if os.path.exists(pkgfilepath):
                with open(pkgfilepath) as pfile:
                    text_data += pfile.read()

        if enable_json:
            pkgfilepath = d.getVar("CVE_CHECK_RECIPE_FILE_JSON")
            if os.path.exists(pkgfilepath):
                with open(pkgfilepath) as j:
                    data = json.load(j)
                    cve_check_merge_jsons(json_data, data)

    d.setVar("PN", save_pn)

    if enable_text:
        link_path = os.path.join(deploy_dir, "%s.cve" % link_name)
        manifest_name = d.getVar("CVE_CHECK_MANIFEST")

        with open(manifest_name, "w") as f:
            f.write(text_data)

        update_symlinks(manifest_name, link_path)
        d.logger.info("Image CVE report stored in: %s" % manifest_name)

    if enable_json:
        link_path = os.path.join(deploy_dir, "%s.json" % link_name)
        manifest_name = d.getVar("CVE_CHECK_MANIFEST_JSON")

        with open(manifest_name, "w") as f:
            json.dump(json_data, f, indent=2)

        update_symlinks(manifest_name, link_path)
        d.logger.info("Image CVE JSON report stored in: %s" % manifest_name)


# ROOTFS_POSTPROCESS_COMMAND:prepend = "${@'cve_check_write_rootfs_manifest ' if d.getVar('CVE_CHECK_CREATE_MANIFEST') == '1' else ''}"
# do_rootfs[recrdeptask] += "${@'do_cve_check' if d.getVar('CVE_CHECK_CREATE_MANIFEST') == '1' else ''}"
# do_populate_sdk[recrdeptask] += "${@'do_cve_check' if d.getVar('CVE_CHECK_CREATE_MANIFEST') == '1' else ''}"


def cve_is_ignored(d, cve_data, cve):
    if cve not in cve_data:
        return False
    if cve_data[cve]["abbrev-status"] == "Ignored":
        return True
    return False


def cve_is_patched(d, cve_data, cve):
    if cve not in cve_data:
        return False
    if cve_data[cve]["abbrev-status"] == "Patched":
        return True
    return False


def check_cves(d, cve_data):
    """
    Connect to the NVD database and find unpatched cves.
    """

    pn = d.getVar("PP")
    real_pv = d.getVar("PV")
    suffix = d.getVar("CVE_VERSION_SUFFIX")

    cves_status = []
    cves_in_recipe = False
    # CVE_PRODUCT can contain more than one product (eg. curl/libcurl)
    products = d.getVar("CVE_PRODUCT").split()
    # If this has been unset then we're not scanning for CVEs here (for example, image recipes)
    if not products:
        return ([], [])
    pv = d.getVar("CVE_VERSION").split("+git")[0]

    # If the recipe has been skipped/ignored we return empty lists
    if pn in d.getVar("CVE_CHECK_SKIP_RECIPE").split():
        d.logger.debug("Recipe has been skipped by cve-check")
        return ([], [])

    db = d.getDatabaseConnection()

    # For each of the known product names (e.g. curl has CPEs using curl and libcurl)...
    for product in products:
        cves_in_product = False
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = "%"

        cves_in_product = db.update_status(
            d, product, pv, pn, vendor, cve_data, cves_status, []
        )
        if cves_in_product:
            cves_in_recipe = True

        if not cves_in_product:
            d.logger.debug("No CVE records found for product %s, pn %s" % (product, pn))
            cves_status.append([product, False])

    if not cves_in_recipe:
        d.logger.debug("No CVE records for products in recipe %s" % (pn))

    return (cve_data, cves_status)


def get_cve_info(d, cve_data):
    """
    Get CVE information from the database.
    """
    db = d.getDatabaseConnection()

    db.get_cve_info(d, cve_data)

    return cve_data


def cve_write_data_text(d, cve_data):
    """
    Write CVE information in WORKDIR; and to CVE_CHECK_DIR, and
    CVE manifest if enabled.
    """

    cve_file = d.getVar("CVE_CHECK_LOG")
    fdir_name = d.getVar("FILE_DIRNAME")
    layer = fdir_name.split("/")[-3]

    include_layers = d.getVar("CVE_CHECK_LAYER_INCLUDELIST").split()
    exclude_layers = d.getVar("CVE_CHECK_LAYER_EXCLUDELIST").split()

    report_all = d.getVar("CVE_CHECK_REPORT_PATCHED") == "1"

    if exclude_layers and layer in exclude_layers:
        return

    if include_layers and layer not in include_layers:
        return

    # Early exit, the text format does not report packages without CVEs
    if not len(cve_data):
        return

    nvd_link = "https://nvd.nist.gov/vuln/detail/"
    write_string = ""
    unpatched_cves = []
    bb.utils.mkdirhier(os.path.dirname(cve_file))

    for cve in sorted(cve_data):
        write_string += "LAYER: %s\n" % layer
        write_string += "PACKAGE NAME: %s\n" % d.getVar("PN")
        write_string += "PACKAGE VERSION: %s%s\n" % (
            d.getVar("EXTENDPE"),
            d.getVar("PV"),
        )
        write_string += "CVE: %s\n" % cve
        write_string += "CVE STATUS: %s\n" % cve_data[cve]["abbrev-status"]

        if "status" in cve_data[cve]:
            write_string += "CVE DETAIL: %s\n" % cve_data[cve]["status"]
        if "justification" in cve_data[cve]:
            write_string += "CVE DESCRIPTION: %s\n" % cve_data[cve]["justification"]

        if "NVD-summary" in cve_data[cve]:
            write_string += "CVE SUMMARY: %s\n" % cve_data[cve]["NVD-summary"]
            write_string += "CVSS v2 BASE SCORE: %s\n" % cve_data[cve]["NVD-scorev2"]
            write_string += "CVSS v3 BASE SCORE: %s\n" % cve_data[cve]["NVD-scorev3"]
            write_string += "VECTOR: %s\n" % cve_data[cve]["NVD-vector"]
            write_string += "VECTORSTRING: %s\n" % cve_data[cve]["NVD-vectorString"]

        write_string += "MORE INFORMATION: %s%s\n\n" % (nvd_link, cve)
        if cve_data[cve]["abbrev-status"] == "Unpatched":
            unpatched_cves.append(cve)

    if unpatched_cves and d.getVar("CVE_CHECK_SHOW_WARNINGS") == "1":
        d.logger.warning(
            "Found unpatched CVE (%s), for more information check %s"
            % (" ".join(unpatched_cves), cve_file)
        )

    with open(cve_file, "w") as f:
        d.logger.debug("Writing file %s with CVE information" % cve_file)
        f.write(write_string)

    if d.getVar("CVE_CHECK_COPY_FILES") == "1":
        deploy_file = d.getVar("CVE_CHECK_RECIPE_FILE")
        bb.utils.mkdirhier(os.path.dirname(deploy_file))
        with open(deploy_file, "w") as f:
            f.write(write_string)

    if d.getVar("CVE_CHECK_CREATE_MANIFEST") == "1":
        cvelogpath = d.getVar("CVE_CHECK_SUMMARY_DIR")
        bb.utils.mkdirhier(cvelogpath)

        with open(d.getVar("CVE_CHECK_TMP_FILE"), "a") as f:
            f.write("%s" % write_string)


def cve_check_write_json_output(d, output, direct_file, deploy_file, manifest_file):
    """
    Write CVE information in the JSON format: to WORKDIR; and to
    CVE_CHECK_DIR, if CVE manifest if enabled, write fragment
    files that will be assembled at the end in cve_check_write_rootfs_manifest.
    """

    write_string = json.dumps(output, indent=2)
    with open(direct_file, "w") as f:
        d.logger.debug("Writing file %s with CVE information" % direct_file)
        f.write(write_string)

    if d.getVar("CVE_CHECK_COPY_FILES") == "1":
        bb.utils.mkdirhier(os.path.dirname(deploy_file))
        with open(deploy_file, "w") as f:
            f.write(write_string)

    if d.getVar("CVE_CHECK_CREATE_MANIFEST") == "1":
        cvelogpath = d.getVar("CVE_CHECK_SUMMARY_DIR")
        index_path = d.getVar("CVE_CHECK_SUMMARY_INDEX_PATH")
        bb.utils.mkdirhier(cvelogpath)
        fragment_file = os.path.basename(deploy_file)
        fragment_path = os.path.join(cvelogpath, fragment_file)
        with open(fragment_path, "w") as f:
            f.write(write_string)
        with open(index_path, "a+") as f:
            f.write("%s\n" % fragment_path)


def cve_write_data_json(d, cve_data, cve_status):
    """
    Prepare CVE data for the JSON format, then write it.
    """

    output = {"version": "1", "package": []}
    nvd_link = "https://nvd.nist.gov/vuln/detail/"

    layer = d.getLayer()

    include_layers = d.getVar("CVE_CHECK_LAYER_INCLUDELIST").split()
    exclude_layers = d.getVar("CVE_CHECK_LAYER_EXCLUDELIST").split()

    report_all = d.getVar("CVE_CHECK_REPORT_PATCHED") == "1"

    if exclude_layers and layer in exclude_layers:
        return

    if include_layers and layer not in include_layers:
        return

    product_data = []
    for s in cve_status:
        p = {"product": s[0], "cvesInRecord": "Yes"}
        if s[1] == False:
            p["cvesInRecord"] = "No"
        product_data.append(p)

    package_version = "%s%s" % (d.getVar("EXTENDPE"), d.getVar("PV"))
    package_data = {
        "name": d.getVar("PN"),
        "layer": layer,
        "version": package_version,
        "products": product_data,
    }
    if d.getVar("CPE_table") is not None:
        package_data["cpes"] = list(d.getVar("CPE_table"))[0]

    for _, data in cve_data.items():
        if "cpes" in data.keys() and "cpes" in package_data.keys():
            package_data["cpes"] = list(set(package_data["cpes"] + data["cpes"]))
        elif "cpes" in data.keys():
            package_data["cpes"] = data["cpes"]

    cve_list = []

    for cve in sorted(cve_data):
        issue_link = "%s%s" % (nvd_link, cve)

        cve_item = {
            "id": cve,
            "status": cve_data[cve]["abbrev-status"],
            "link": issue_link,
        }

        if "NVD-summary" in cve_data[cve]:
            cve_item["summary"] = cve_data[cve]["NVD-summary"]
            cve_item["scorev2"] = cve_data[cve]["NVD-scorev2"]
            cve_item["scorev3"] = cve_data[cve]["NVD-scorev3"]
            cve_item["vector"] = cve_data[cve]["NVD-vector"]
            cve_item["vectorString"] = cve_data[cve]["NVD-vectorString"]
        if "CVE-summary" in cve_data[cve]:
            cve_item["summary"] = cve_data[cve]["CVE-summary"]
        if "CVE-scorev2" in cve_data[cve]:
            cve_item["scorev2"] = cve_data[cve]["CVE-scorev2"]
        if "CVE-scorev31" in cve_data[cve]:
            cve_item["scorev3"] = cve_data[cve]["CVE-scorev31"]
            cve_item["vectorString"] = cve_data[cve]["CVE-vectorString"]
        if "status" in cve_data[cve]:
            cve_item["detail"] = cve_data[cve]["status"]
        if "description" in cve_data[cve]:
            cve_item["description"] = cve_data[cve]["description"]
        if "resource" in cve_data[cve]:
            cve_item["patch-file"] = cve_data[cve]["resource"]
        if "adp-title" in cve_data[cve]:
            cve_item["adp-title"] = cve_data[cve]["adp-title"]
        if "CVE-ssvc" in cve_data[cve]:
            cve_item["CVE-ssvc"] = cve_data[cve]["CVE-ssvc"]
        cve_list.append(cve_item)

    package_data["issue"] = cve_list
    output["package"].append(package_data)

    direct_file = d.getVar("CVE_CHECK_LOG_JSON")
    deploy_file = d.getVar("CVE_CHECK_RECIPE_FILE_JSON")
    manifest_file = d.getVar("CVE_CHECK_SUMMARY_FILE_NAME_JSON")

    cve_check_write_json_output(d, output, direct_file, deploy_file, manifest_file)


def cve_write_data(d, cve_data, status):
    """
    Write CVE data in each enabled format.
    """

    if d.getVar("CVE_CHECK_FORMAT_TEXT") == "1":
        cve_write_data_text(d, cve_data)
    if d.getVar("CVE_CHECK_FORMAT_JSON") == "1":
        cve_write_data_json(d, cve_data, status)


def do_cve_check_product(d, package, product, version):
    d.setPN(package)
    d.setProduct(product)
    d.setPV(version)
    d.setVEXTable(get_related_vexs(d, d.getVEXPath(), product, version))
    do_cve_check(d)
    d.resetVEXTable()
    d.resetPN()
    d.resetProduct()
    d.resetPV()
    d.resetLayer()


def cve_check_from_spdx(d):
    with open(d.getSPDXPath()) as f:
        data = json.load(f)
        for el in data:
            for name, details in el.items():
                packages = get_package_info_spdx(details, data)
                for p in packages:
                    if p["cpe"] is not None:
                        d.setCPETable(p["cpe"])
                    do_cve_check_product(d, p["name"], p["product"], p["version"])
                    d.resetCPETable()


def cve_check_from_cve(d):
    with open(d.getCVEPath()) as f:
        data = json.load(f)
        for el in data["package"]:
            packages = get_package_info_cve(el)
            for p in packages:
                d.setLayer(p["layer"])
                if p["cpe"] is not None:
                    d.setCPETable(p["cpe"])
                do_cve_check_product(d, p["name"], p["product"], p["version"])
                d.resetCPETable()


def cve_check_from_file(d):

    # Using CVE summary to get package info
    if d.getCVEPath() is not None:
        cve_check_from_cve(d)

    # Using SPDX summary to get package info
    elif d.getSPDXPath() is not None:
        cve_check_from_spdx(d)

    cve_summary_name = d.getVar("CVE_CHECK_SUMMARY_FILE_NAME_JSON")
    if not os.path.exists(cve_summary_name):
        open(cve_summary_name, mode="w").close()
    cve_save_summary_handler(d)
