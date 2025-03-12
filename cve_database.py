#from cve_check import CheckerConfig
from databases import Database, VexStatus
import os
import json
import re
from versions import SemanticVersioning, OpenSSLVersioning, BaseCustomVersion, versions_factory, versionType



class CVEProduct:
    def __init__(self, cve_id :str, affected :dict):
        self.__cveID :str = cve_id
        self.__affected_dict :dict = affected
        product :str
        vendor :str

        if 'vendor' in self.__affected_dict and  'product' in self.__affected_dict:
            # is product
            product = self.__affected_dict["product"]
            vendor = self.__affected_dict["vendor"]
        elif 'collectionURL'  in self.__affected_dict and 'packageName' in self.__affected_dict:
            # isOpensource
            product = self.__affected_dict["packageName"]
            vendor = self.__affected_dict["collectionURL"]

        self.__productName: str = product
        self.__vendor: str = vendor

    def get_product(self):
        return self.__productName

    def get_vendor(self):
        return self.__vendor

    def get_cve_id(self):
        return self.__cveID

    def get_vex_status(self, d,version_str :str) -> VexStatus:
        """
        Computes weather the given product version is affected by this CVE
        Args:
            d (CheckerConfig): Config Object for logging
            version_str (str): specific version we want to test for

        Returns:
            VexStatus: of the CVEProduce with the given version
        """
        req_version: BaseCustomVersion = versions_factory(version_str)
        if not req_version:
            raise ValueError("Unsupported version format!")

        #No version -> Default status!
        if "versions" not in self.__affected_dict:
            if "defaultStatus" in self.__affected_dict:
                if self.__affected_dict["defaultStatus"] == VexStatus.AFFECTED.value:
                    return VexStatus.AFFECTED
                elif self.__affected_dict["defaultStatus"] == VexStatus.UNAFFECTED.value:
                    return VexStatus.UNAFFECTED
            return VexStatus.UNKNOWN


        for version_dict in self.__affected_dict["versions"]:

            if "version" not in version_dict:
                d.logger.info("Entry without version... skipping " + str(version_dict))
                return VexStatus.UNKNOWN

            #@TODO Check this complient to original? and Parsing pattern?
            # Skip unsopprted custom versions patterns
            less_than_version = None
            less_than_or_equal_version = None


            if "versionType" in version_dict and version_dict["versionType"] == versionType.CUSTOM.value:
                if "lessThan" in version_dict:
                    less_than_version = versions_factory(version_dict["lessThan"])

                if "lessThanOrEqual" in version_dict:
                    less_than_or_equal_version = versions_factory(version_dict["lessThanOrEqual"])

                if not less_than_version or not less_than_or_equal_version:
                    # Skip since unknowen and currently not supported version type
                    d.logger.info("Entry version is unsupported... skipping " + str(version_dict))
                    continue

            elif "versionType" in version_dict and version_dict["versionType"] == versionType.GIT.value:
                # Skip git versions, since currently not supported
                d.logger.info("Entry version git is unsupported... skipping " + str(version_dict))
                continue

            # Check for single affected version entryies, with unknowen version type
            # Entries like  'versions': [{'status': 'affected', 'version': '3.5.12'}]}
            if (version_dict["status"] == VexStatus.AFFECTED.value) and "versionType" not in version_dict:
                target_version = versions_factory(version_dict["version"])
                if not target_version:
                    d.logger.info("Malformed entry, missing version type and unsupported version format ... skipping " + str(version_dict))
                    return VexStatus.UNKNOWN
                if target_version == req_version:
                    return VexStatus.AFFECTED
            elif version_dict["status"] == VexStatus.AFFECTED.value and version_dict["versionType"] == "semver":
                target_version = SemanticVersioning(version_dict["version"])
                if target_version == req_version:
                    return VexStatus.AFFECTED
                elif "lessThanOrEqual" in version_dict:
                    less_then_eq = SemanticVersioning(version_dict["lessThanOrEqual"])
                    if target_version < req_version <= less_then_eq:
                        return VexStatus.AFFECTED
                elif "lessThan" in version_dict:
                    less_then = SemanticVersioning(version_dict["lessThan"])
                    if target_version < req_version < less_then:
                        return VexStatus.AFFECTED

            elif version_dict["status"] == "affected" and version_dict["versionType"] == "custom":
                target_version = versions_factory(version_dict["version"])
                if target_version == req_version:
                    return VexStatus.AFFECTED
                elif "lessThanOrEqual" in version_dict:
                    less_then_eq = versions_factory(version_dict["lessThanOrEqual"])
                    if target_version < req_version <= less_then_eq:
                        return VexStatus.AFFECTED
                elif "lessThan" in version_dict:
                    less_then = versions_factory(version_dict["lessThan"])
                    if target_version < req_version < less_then:
                        return VexStatus.AFFECTED

        return VexStatus.UNAFFECTED


    def get_cpe_vendor_products(self) -> list[(float, float)]:#

        """
        Provides the CPEs marked in the product of the CVE file
        Returns:
            list[(float, float)]: list of tuples (vendor, Product) or empty list
        """

        cpes_venor_products = []
        if "cpes" in self.__affected_dict:
            for cpe in self.__affected_dict["cpes"]:
                cpe_vendor = cpe.split(":")[3]
                cpe_product = cpe.split(":")[4]
                cpes_venor_products.append((cpe_vendor,cpe_product))
        return cpes_venor_products


class CVEDatabase(Database):
    def __init__(self, path :str):
        """
        Reads all CVE files, and store them in the products_sorted list and cves dictinary for later lookup
        Args:
            path (str): string to the root of the CVEProject Database
        """
        self.path = path
        self.cves = {}
        products = []
        for root, dirnames, filenames in os.walk(self.path):
            for filename in filenames:
                year, number = self.__parse_cve_id(filename)
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
                                                    CVEProduct(cve_id=cve_id,
                                                            affected=x)
                                                )
                                elif "cna" in data["containers"]:
                                    if "affected" in data["containers"]["cna"]:
                                        for x in data["containers"]["cna"]["affected"]:
                                            products.append(
                                                CVEProduct(cve_id= cve_id, affected=x)
                                            )
                            self.cves[cve_id] = data
                        except KeyError:
                            pass
                        except TypeError:
                            pass

        self.products_sorted = sorted(products, key=lambda product: product.get_product())

    @staticmethod
    def __parse_cve_id(cve):
        pattern = r"CVE-(\d{4})-(\d+)\.json"
        match = re.match(pattern, cve)
        if match:
            year = match.group(1)
            number = match.group(2)
            return year, number
        else:
            return None, None

    def connexion(self):
        """
        provide preloaded product list

        Returns:
            VexStatus: list of CVE Products or None
        """
        return self.products_sorted

    def get_cve_info(self,config, cve_data:dict):
        """
        Modifies and enriches the provided cve_data dict, with the preloaded information in the cves dictinary
        Args:
            config (CheckerConfig): for logging reasons
            cve_data (dict): in and out parameter containing cve_data list of considered CVE's

        Returns:
            dict: of enriched cve_data
        """

        for cve in cve_data:
            if cve not in self.cves:
                #print("ERRROR: no entry for " + cve)
                config.logger.info("no entry for " + cve)
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

    def update_status(self, d, product_name :str, product_version :str, package_name, vendor :str, cve_data :dict, cves_status:list, loop:list):
        """
        Modifies and enriches the provided cve_data dict, with the preloaded information in the cves dictinary
        Args:
            d (CheckerConfig): for logging
            product_name (str): Name of the product to check for
            product_version (str): Version of the product
            package_name (str): ??? Needed ???
            vendor (str): Name of the vendor
            cve_data (dict): cve dictionary containing infos about the CVE
            cves_status (list): ??? Needed ???
            loop (list): list of loops to avoid infinite recursion

        Returns:
            dict: of enriched cve_data
        """

        if vendor == "%":
            vendor = "*"

        # Store vendor-product pair to avoid infinite loop
        loop.append(f"{vendor}-{product_name}")
        loop = list(set(loop))
        for pr in self.products_sorted:
            if pr.get_product().lower() == product_name and ((vendor == "*") or (vendor.lower() == pr.get_vendor().lower())):
                cve = pr.get_cve_id()
                vuln_status = pr.get_vex_status(d, product_version)# self.is_affected(d, cve, pr[1], version)
                if vuln_status == VexStatus.AFFECTED:
                    Database.cve_update(
                        d,
                        cve_data,
                        cve,
                        {"abbrev-status": "Unpatched", "status": "version-in-range"},
                    )
                    print(pr.get_cve_id() + ": affected: " + product_name + " " + product_version)
                elif vuln_status == VexStatus.UNKNOWN:
                    print(pr.get_cve_id() + ": unknown status: " + product_name + " " + product_version)
                    Database.cve_update(d, cve_data, cve, {"abbrev-status": "Unknown"})
                elif vuln_status == VexStatus.UNAFFECTED:
                    print(pr.get_cve_id() + ": not affected " + product_name + " " + product_version)
                    Database.cve_update(
                        d,
                        cve_data,
                        cve,
                        {"abbrev-status": "Patched", "status": "version-not-in-range"},
                    )

                for cpe_vendor, cpe_product in pr.get_cpe_vendor_products():
                    if f"{cpe_vendor}-{cpe_product}" not in loop:
                        if cpe_vendor.lower() != vendor.lower() or cpe_product != product_name:
                            self.update_status(
                                d,
                                cpe_product,
                                product_version,
                                package_name,
                                cpe_vendor,
                                cve_data,
                                cves_status,
                                loop,
                            )


    def close(self):
        pass
