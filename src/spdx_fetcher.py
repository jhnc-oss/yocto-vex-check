#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import os
import json
import logging
import zstandard
import tarfile
import tempfile
from glob import glob


class SpdxFetcher:

    BUILD_DIR = "/build/tmp-glibc"
    DEPLOY_DIR = "deploy/images"
    MACHINE = "qemux86-64"
    SPDX_EXTRACTED_INFO_PATH = "spdx-sum.json"
    PACKAGE_INFO_SUFFIX = "_pkg_info.json"
    BASE_PATH = "data"

    def getVar(self, variable):
        if variable == "DEPLOY_DIR":
            return os.path.join(self.BUILD_DIR, self.DEPLOY_DIR)
        elif variable == "SPDX_EXTRACTED_INFO_PATH":
            return os.path.join(
                os.getcwd(), self.BASE_PATH, self.SPDX_EXTRACTED_INFO_PATH
            )
        elif variable == "PACKAGE_INFO_PATH":
            return (
                os.path.join(os.getcwd(), self.BASE_PATH, self.MACHINE)
                + self.PACKAGE_INFO_SUFFIX
            )
        elif variable == "PACKAGE_INFO_NAME":
            return self.MACHINE + self.PACKAGE_INFO_SUFFIX
        elif variable == "MACHINE":
            return self.MACHINE
        elif variable == "PACKAGE_INFO_SUFFIX":
            return self.PACKAGE_INFO_SUFFIX
        elif variable == "BASE_PATH":
            return os.path.join(os.getcwd(), self.BASE_PATH)
        else:
            return None

    def setMachine(self, machine):
        self.MACHINE = machine


def extract_zst(input_path, output_dir):
    dctx = zstandard.ZstdDecompressor()

    with tempfile.TemporaryFile(suffix=".tar") as ofh:
        with open(input_path, "rb") as ifh:
            dctx.copy_stream(ifh, ofh)
        ofh.seek(0)
        with tarfile.open(fileobj=ofh) as z:
            z.extractall(output_dir)

    return output_dir


def findall_spdx_path(d, root):
    machine = d.getVar("MACHINE")
    tmp = glob(f"{root}/*.rootfs.spdx.tar.zst")
    if len(tmp) > 0:
        for path in tmp:
            if os.path.isfile(path):
                build_name = path.split("/")[-1].split(machine)[0][:-1]
                return build_name, path
    else:
        tmp = glob(f"{root}/*.spdx.tar.zst")
        if len(tmp) > 0:
            for path in tmp:
                if os.path.isfile(path):
                    build_name = path.split("/")[-1].split(machine)[0][:-1]
                    return build_name, path

    d.logger.error(f"No SPDX tarfile found in {root}")
    return None, None


def get_spdx_info(d, root):
    build_name, path = findall_spdx_path(d, root)
    output_dir = extract_zst(
        path, os.path.join(d.getVar("BASE_PATH"), f'spdx-{d.getVar("MACHINE")}')
    )
    info = []

    for p in os.listdir(output_dir):
        if p == "index.json" or build_name in p:
            continue
        t = "package"
        recipe_name = ""
        pkgs_recipe = []
        pkg_name = ""
        pkg_version = ""
        filename = p.split("/")[-1]
        if "recipe" in filename:
            t = "recipe"
        elif "runtime" in filename:
            t = "runtime"
        with open(os.path.join(output_dir, p)) as f:
            data = json.load(f)
            spdx_info = {filename: {"filename": filename, "path": p, "type": t}}
            if t == "recipe":
                recipe_name = data["name"]
                for package in data["packages"]:
                    cpe = []
                    if "externalRefs" in package.keys():
                        cpe = [
                            ref["referenceLocator"]
                            for ref in package["externalRefs"]
                            if ref["referenceCategory"] == "SECURITY"
                            and ref["referenceLocator"][0:3] == "cpe"
                        ]
                    if "versionInfo" in package.keys():
                        pkgs_recipe.append(
                            {
                                "name": package["name"],
                                "version": package["versionInfo"],
                                "cpe": cpe,
                            }
                        )
                spdx_info[filename]["recipe_name"] = recipe_name
                spdx_info[filename]["pkgs_recipe"] = pkgs_recipe
            elif t == "package":
                pkg_name = data["packages"][0]["name"]
                pkg_version = data["packages"][0]["versionInfo"]
                spdx_info[filename]["pkg_name"] = pkg_name
                spdx_info[filename]["pkg_version"] = pkg_version
                if "externalDocumentRefs" in data.keys():
                    related_recipe = data["externalDocumentRefs"][0][
                        "externalDocumentId"
                    ][len("DocumentRef-") :]
                    spdx_info[filename]["related_recipe"] = related_recipe
            info.append(spdx_info)

    return info


def write_package_info_only(dest, logger, *data):
    p_cpe = {}
    p_vers = {}

    data = list(data)[0]

    # Extract cpe in recipes
    for el in data:
        for k, v in el.items():
            if v["type"] == "recipe":
                c = [{"name": pk["name"], "cpe": pk["cpe"]} for pk in v["pkgs_recipe"]]
                p_cpe[k] = c
    # Extract version in package
    for el in data:
        for k, v in el.items():
            if v["type"] == "package":
                p_vers[v["pkg_name"]] = {
                    "version": v["pkg_version"],
                    "related_recipe": f'{v["related_recipe"]}.spdx.json',
                }

    # Match
    pkgs = []
    for k, v in p_vers.items():
        if v["related_recipe"] in p_cpe.keys():
            p = {}
            p[k] = v
            c = []
            for pkg in p_cpe[v["related_recipe"]]:
                if pkg["name"] in k:
                    c += pkg["cpe"]
            p[k]["cpe"] = c
            pkgs.append(p)
        else:
            logger.error(f"No recipe found for package {k}")

    with open(dest, "w") as jsonfile:
        json.dump(pkgs, jsonfile, indent=2)


def write_spdx_info(d, logger, all_arch_flag):
    deploy_path = []
    if all_arch_flag:
        tmp = glob(f'{d.getVar("DEPLOY_DIR")}/*')
        deploy_path = tmp
    else:
        deploy_path.append(os.path.join(d.getVar("DEPLOY_DIR"), d.getVar("MACHINE")))

    for p in deploy_path:
        logger.debug(f'Getting SPDX info for machine : {d.getVar("MACHINE")}')
        if os.path.exists(p):
            spdx_data = get_spdx_info(d, p)
        else:
            logger.error("Spdx dir not found")
            return

        if not os.path.exists(d.getVar("SPDX_EXTRACTED_INFO_PATH")):
            with open(d.getVar("SPDX_EXTRACTED_INFO_PATH"), "w") as file:
                json.dump(spdx_data, file, indent=2)
        else:
            json_data = []
            with open(d.getVar("SPDX_EXTRACTED_INFO_PATH"), "r") as rfile:
                data = json.load(rfile)
            json_data = data + spdx_data
            with open(d.getVar("SPDX_EXTRACTED_INFO_PATH"), "w") as wfile:
                json.dump(json_data, wfile, indent=2)

        write_package_info_only(d.getVar("PACKAGE_INFO_PATH"), logger, spdx_data)
