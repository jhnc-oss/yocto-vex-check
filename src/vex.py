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
from vex_lib import read_vex

import datetime


class Vex:

    CVE_CHECK_LOG_JSON = "cve-summary.json"

    BASE_PATH = "data"
    VEX_SUMMARY = "vex-summary.json"

    BUILD_DIR = "build/tmp-glibc"
    DEPLOY_DIR = "deploy/spdx"
    SSTATE_ARCH = "qemux86_64"
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
            arch = self.SSTATE_ARCH
            if arch == "qemux86_64":
                arch = "qemux86-64"
            return os.path.join(
                os.getcwd(), self.BASE_PATH, arch + self.SPDX_PKG_INFO
            )
        elif variable == "SPDX_PKG_INFO_NAME":
            arch = self.SSTATE_ARCH
            if arch == "qemux86_64":
                arch = "qemux86-64"
            return os.path.join(self.BASE_PATH, arch + self.SPDX_PKG_INFO)
        else:
            return None

    def setBuildPath(self, path):
        self.BUILD_DIR = path

    def setArch(self, arch):
        self.SSTATE_ARCH = arch

    def setCvePath(self, path):
        self.CVE_CHECK_LOG_JSON = path


def get_cves(d, logger):
    cves = None
    cve_summary_path = d.getVar("CVE_CHECK_LOG_JSON")
    logger.info(f"Getting CVE log from: {cve_summary_path}")

    with open(cve_summary_path) as file:
        try:
            cves = json.load(file)
        except Error as e:
            logger.error(f"{e} -- VEX generation stopped")

    return cves


def update_spdx(vex_id, spdx_filepath):
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

def find_spdx_file(spdxdir, pkg_name):
    for file in os.listdir(os.path.join(spdxdir, "recipes")):
        if pkg_name in file:
            return os.path.join(spdxdir, "packages", file)
    for file in os.listdir(os.path.join(spdxdir, "packages")):
        if pkg_name in file:
            return os.path.join(spdxdir, "packages", file)
    return None

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
        return 1
    vexs = get_vexs_from_cves(timestamp, cve_data)

    if vexs:
        logger.info("Generating JSON VEX summary")

        with open(vexpath, "w") as f:
            json.dump(vexs, f, indent=2)
        logger.info(f"Complete JSON VEX summary created at: {vexpath}")

        for k, v in vexs.items():
            with open(f"{vexdir}/vex_{k}.json", "w") as f:
                json.dump(v, f, indent=2)
    else:
        with open(vexpath, "w") as f:
            json.dump({}, f, indent=2)
        logger.info(f"Empty VEX summary created at: {vexpath}")

    return 0


def update_spdx_from_file(d, logger):
    vexdir = os.path.join(d.getVar("BASE_PATH"), "vex")
    spdxdir = d.getVar("SPDX_DIR")

    # Match package name with spdx files listed in spdx pkg info
    if os.path.exists(d.getVar("SPDX_PKG_INFO")):
        spdx_summary = {}
        spdx_summary_path = d.getVar("SPDX_PKG_INFO")

        with open(spdx_summary_path) as file:
            spdx_summary = json.load(file)

        if not os.path.exists(spdxdir):
            logger.error(f"SPDX folder not found ({spdxdir})")
            return

        for vexfile in os.listdir(vexdir):
            vex_data = read_vex(os.path.join(vexdir, vexfile))
            if vex_data:
                match_vex_spdx_with_summary(d, vex_data, spdx_summary)
            else:
                logger.warning(f"Vex file {vexfile} empty")

    # Use package name to find spdx files
    else:
        for vexfile in os.listdir(vexdir):
            vex_data = read_vex(os.path.join(vexdir, vexfile))
            if vex_data:
                all_products = [p["@id"][len("pkg:"):] for s in vex_data["statements"] for p in s["products"]]
                for p in all_products:
                    spdx_path = find_spdx_file(spdxdir, p)
                    if spdx_path is not None:
                        update_spdx(vex_data["@id"], spdx_path)
                        logger.info(f"{spdx_path} updated")
                    else:
                        logger.warning(f"Spdx file not found for product {p}")
            else:
                logger.warning(f"Vex file {vexfile} empty")
    return 0