#!/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
import json


def validate_SPDX(data, path):
    keys = [v.keys() for el in data for v in el.values()]
    for el in keys:
        if "filename" not in el:
            return False, f'JSON error, "filename" key is missing in {path}'
        if "path" not in el:
            return False, f'JSON error, "path" key is missing in {path}'
        if "type" not in el:
            return False, f'JSON error, "type" key is missing in {path}'
    return True, "Valid SPDX JSON"


def validate_VEX(data, path):
    for k, v in data.items():
        if "CVE-" not in k:
            return False, f"JSON error, malformed key found in {path}"
        elif "@id" not in v.keys():
            return False, f'JSON error, "@id" key is missing in {path}'
        elif "author" not in v.keys():
            return False, f'JSON error, "author" key is missing in {path}'
        elif "role" not in v.keys():
            return False, f'JSON error, "role" key is missing in {path}'
        elif "timestamp" not in v.keys():
            return False, f'JSON error, "timestamp" key is missing in {path}'
        elif "version" not in v.keys():
            return False, f'JSON error, "version" key is missing in {path}'
        elif "statements" not in v.keys():
            return False, f'JSON error, "statements" key is missing in {path}'
        elif v["statements"] != []:
            for s in v["statements"]:
                if "vulnerability" not in s.keys():
                    return (
                        False,
                        f'JSON error, "vulnerability" key is missing in {path}',
                    )
                elif "products" not in s.keys():
                    return False, f'JSON error, "products" key is missing in {path}'
                elif "status" not in s.keys():
                    return False, f'JSON error, "status" key is missing in {path}'
    return True, "Valid VEX JSON"


def validate_CVE(data, path):
    if "version" not in data.keys():
        return False, f'JSON error, "version" key is missing in {path}'
    elif "package" not in data.keys():
        return False, f'JSON error, "package" key is missing in {path}'
    return True, "Valid CVE JSON"


def validate_schema(data, ftype, path):
    if ftype == "spdx":
        return validate_SPDX(data, path)
    elif ftype == "vex":
        return validate_VEX(data, path)
    elif ftype == "cve":
        return validate_CVE(data, path)
    else:
        return False, "JSON summary type not found {vex | cve | spdx}"


def json_verify(path, ftype, logger):
    try:
        with open(path, "r") as file:
            data = json.load(file)

    except ValueError as error:
        logger.error(f"Json load verification failed : {error}")
        return False

    response, out = validate_schema(data, ftype, path)
    if not response:
        logger.error(out)
        return False
    else:
        logger.info(out)

    return True
