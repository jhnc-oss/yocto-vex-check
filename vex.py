#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import logging
import shutil
import json
import os
import configparser
from vex_lib import get_vexs_from_cves
from vex_lib import get_cve_data
from vex_lib import read_vex

import datetime


class Vex:

    CVE_CHECK_LOG_JSON = "cve-summary.json"

    BASE_PATH = "data"
    VEX_SUMMARY = "vex-summary.json"

    BUILD_DIR = "build/tmp-glibc"
    DEPLOY_DIR = "deploy/spdx"
    SSTATE_ARCH = "core2-64"
    SPDX_PKG_INFO = "_pkg_info.json"

    def getVar(self, variable):
        if variable == "CVE_CHECK_LOG_JSON":
            return self.CVE_CHECK_LOG_JSON
        elif variable == "BASE_PATH":
            return os.path.join(os.getcwd(), self.BASE_PATH)
        elif variable == "VEX_SUMMARY":
            return self.VEX_SUMMARY
        elif variable == "VEX_SUMMARY_PATH":
            return os.path.join(os.getcwd(), self.BASE_PATH, self.VEX_SUMMARY)
        elif variable == "SSTATE_ARCH":
            return self.SSTATE_ARCH
        elif variable == "DEPLOY_DIR":
            return self.DEPLOY_DIR
        elif variable == "SPDX_DIR":
            return os.path.join(self.BUILD_DIR, self.DEPLOY_DIR, self.SSTATE_ARCH)
        elif variable == "SPDX_PKG_INFO":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, self.SSTATE_ARCH + self.SPDX_PKG_INFO
            )
        elif variable == "SPDX_PKG_INFO_NAME":
            return os.path.join(self.BASE_PATH, self.SSTATE_ARCH + self.SPDX_PKG_INFO)
        else:
            return None

    def setBuildPath(self, path):
        self.BUILD_DIR = path

    def setArch(self, arch):
        self.SSTATE_ARCH = arch

    def setCvePath(self, path):
        self.CVE_CHECK_LOG_JSON = path


def get_cves(d, logger):

    cve_summary_path = d.getVar("CVE_CHECK_LOG_JSON")
    logger.info(f"Getting CVE log from: {cve_summary_path}")

    if os.path.exists(cve_summary_path):
        return get_cve_data(cve_summary_path)
    else:
        logger.error("CVE summary not found -- VEX generation aborted")
        return None


def update_spdx(vexid, spdx_filepath):
    with open(spdx_filepath) as rjson:
        spdx_data = json.load(rjson)

    if "externalRefs" in spdx_data["packages"][0].keys():
        spdx_data["packages"][0]["externalRefs"].append(
            {
                "referenceCategory": "OTHER",
                "referenceType": "VEX",
                "referenceLocator": vex_id,
            }
        )
    else:
        spdx_data["packages"][0].update(
            {
                "externalRefs": [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "VEX",
                        "referenceLocator": vex_id,
                    }
                ]
            }
        )
    with open(spdx_filepath, "w") as wjson:
        json.dump(spdx_data, wjson)


def match_vex_spdx_with_summary(d, vex_data, spdx_summary):
    vex_id = vex_data["@id"]
    packages = []

    for el in vex_data["statements"]:
        for product in el["products"]:
            packages.append(product["@id"][4:])

    for el in spdx_summary:
        for k, v in el.items():
            if k in packages:
                update_spdx(vex_id, v["path"])
                update_spdx(
                    vex_id,
                    os.path.join(
                        d.getVar("SPDX_DIR"),
                        "recipes",
                        v["related_recipe"] + ".spdx.json",
                    ),
                )


def generate_vex_summary(d, logger):

    vexpath = d.getVar("VEX_SUMMARY_PATH")
    vexdir = os.path.join(d.getVar("BASE_PATH"), "vex")

    if not os.path.exists(vexdir):
        os.makedirs(vexdir)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    cve_data = get_cves(d, logger)
    if cve_data is None:
        logger.error("Error parsing CVE file")
        return
    vexs = get_vexs_from_cves(timestamp, cve_data)

    if vexs:
        logger.debug("Generating JSON VEX summary")

        with open(f"{vexpath}", "w") as f:
            json.dump(vexs, f, indent=2)
        logger.debug(f"Complete JSON VEX summary created at: {vexpath}")

        for k, v in vexs.items():
            with open(f"{vexdir}/vex_{k}.json", "w") as f:
                json.dump(v, f, indent=2)


def update_spdx_from_file(d, logger):
    vexdir = os.path.join(d.getVar("BASE_PATH"), "vex")
    spdx_summary = {}
    spdxdir = d.getVar("SPDX_DIR")
    spdx_summary_path = d.getVar("SPDX_PKG_INFO")

    if not os.path.exists(spdx_summary_path):
        logger.error("SPDX summary file not found")
        return
    else:
        with open(spdx_summary_path) as file:
            spdx_summary = json.load(file)

    if not os.path.exists(spdxdir):
        logger.error(f"SPDX folder not found ({spdxdir})")
        return

    if not os.path.exists(vexdir):
        generate_vex_summary(d, logger, d.getVar("SPDX_PKG_INFO_NAME"))

    for vexfile in os.listdir(vexdir):
        vex_data = read_vex(os.path.join(vexdir, vexfile))
        if vex_data:
            match_vex_spdx_with_summary(d, vex_data, spdx_summary)
        else:
            logger.warning(f"Vex file {vexfile} empty")
