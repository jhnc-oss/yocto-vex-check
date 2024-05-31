#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#

import json
from cve_vex_map import VEX_STATUS


def get_cve_data(cve_summary):
    try:
        with open(cve_summary) as file:
            data = json.load(file)
            return data
    except IndexError:
        return None
    return None


def vex_format():
    vex = {
        "@id": "",
        "author": "OpenEmbedded Core vex standalone",
        "role": "vex standalone",
        "timestamp": "",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": ""},
                "products": [],
                "status": "",
                "status_note": "",
            }
        ],
    }
    return vex


def get_vexs(date, cves):
    vexs = []
    product = {}

    if "name" in cves.keys():
        product["@id"] = f"pkg:{cves['name']}"
    if "products" in cves.keys() and len(cves["products"]) > 0:
        product["products"] = cves["products"][0]["product"]
    if "version" in cves.keys():
        product["version"] = cves["version"]
    if "layer" in cves.keys():
        product["layer"] = cves["layer"]

    if len(cves["issue"]) > 0:
        for issue in cves["issue"]:
            vex = vex_format()
            vex["@id"] = f'https://openembedded/vex/{issue["id"]}'
            vex["timestamp"] = date
            vex["statements"][0]["products"].append(product)
            vex["statements"][0]["vulnerability"]["name"] = issue["id"]

            vex["statements"][0]["status"] = VEX_STATUS[issue["detail"]]
            vex["statements"][0]["status_note"] = issue["detail"]
            if "description" in issue.keys():
                vex["statements"][0]["justification"] = issue["description"]
            if issue["detail"] == "fix-file-included":
                vex["statements"][0][
                    "justification"
                ] = f'Fixed by a patch file {issue["patch-file"]}'
            vexs.append(vex)

    return vexs


def sort_vexs(vexs):
    sorted_vexs = {}

    for el in vexs:
        cve_id = el["statements"][0]["vulnerability"]["name"]
        status = el["statements"][0]["status"]

        if cve_id not in sorted_vexs.keys():
            sorted_vexs[cve_id] = el
        else:
            statuses = [v["status"] for v in sorted_vexs[cve_id]["statements"]]

            if status in statuses:
                index = 0
                for i in range(len(sorted_vexs[cve_id]["statements"])):
                    if status == sorted_vexs[cve_id]["statements"][i]["status"]:
                        index = i
                if el["statements"][0]["status_note"] == sorted_vexs[cve_id][
                    "statements"
                ][index]["status_note"] and (
                    "description" in el["statements"][0].keys()
                    and "description" in sorted_vexs[cve_id]["statements"][index].keys()
                    and el["statements"][0]["description"]
                    == sorted_vexs[cve_id]["statements"][index]["description"]
                    or (
                        "description" not in el["statements"][0].keys()
                        and "description"
                        not in sorted_vexs[cve_id]["statements"][index].keys()
                    )
                ):
                    sorted_vexs[cve_id]["statements"][index]["products"].append(
                        el["statements"][0]["products"][0]
                    )
                else:
                    sorted_vexs[cve_id]["statements"].append(el["statements"][0])
            else:
                sorted_vexs[cve_id]["statements"].append(el["statements"][0])

    return sorted_vexs


def get_vexs_from_cves(date, cves):
    unsorted_vexs = []
    vexs = {}

    try:
        for package in cves["package"]:
            unsorted_vexs += get_vexs(date, package)

        vexs = sort_vexs(unsorted_vexs)
    except:
        print("Error parsing VEXes")

    return vexs


def read_vex(vexpath):
    with open(vexpath) as file:
        data = json.load(file)
        return data
