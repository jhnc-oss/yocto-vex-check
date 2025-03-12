#from cve_check import CheckerConfig
from databases import Database
import os
import sqlite3
from cve_check_lib import (
    Version,
    convert_cve_version,
)


class NVDDatabase(Database):
    def __init__(self, path):
        self.path = path

    def connexion(self):
        """
        Opens Connection to the SQL lite database
        Returns:
            Connection: of the Database or None
        """
        if os.path.exists(self.path):
            db_file = "file:" + self.path + "?mode=ro"
            self.conn = sqlite3.connect(db_file, uri=True)
            return self.conn
        else:
            return None

    def update_status(self, d, product_name, product_version, package_name, vendor, cve_data, cves_status, loop):
        """
        Modifies and enriches the provided cve_data dict, with the preloaded information in the cves dictinary
        Args:
            d (CheckerConfig): for logging
            product_name (str): Name of the product to check for
            product_version (str): Version of the product
            package_name (str): For logging the packages
            vendor (str): Name of the vendor
            cve_data (dict): cve dictionary containing infos about the CVE
            cves_status (list): ??? Needed ???
            loop (list): list of loops to avoid infinite recursion

        Returns:
            dict: of enriched cve_data
        """
        # Find all relevant CVE IDs.
        real_pv = d.getVar("PV")
        suffix = d.getVar("CVE_VERSION_SUFFIX")

        cve_cursor = self.conn.execute(
            "SELECT DISTINCT ID FROM PRODUCTS WHERE PRODUCT IS ? AND VENDOR LIKE ?",
            (product_name, vendor),
        )
        for cverow in cve_cursor:
            cve = cverow[0]

            if NVDDatabase.__cve_is_ignored(cve_data, cve):
                d.logger.debug("%s-%s ignores %s" % (product_name, product_version, cve))
                continue
            elif NVDDatabase.__cve_is_patched(cve_data, cve):
                d.logger.debug("%s has been patched" % (cve))
                continue

            vulnerable = False
            ignored = False

            product_cursor = self.conn.execute(
                "SELECT * FROM PRODUCTS WHERE ID IS ? AND PRODUCT IS ? AND VENDOR LIKE ?",
                (cve, product_name, vendor),
            )
            for row in product_cursor:
                (_, _, _, version_start, operator_start, version_end, operator_end) = row
                if NVDDatabase.__cve_is_ignored(cve_data, cve):
                    ignored = True

                version_start = convert_cve_version(version_start)
                version_end = convert_cve_version(version_end)

                if (
                        operator_start == "=" and product_version == version_start
                ) or version_start == "-":
                    vulnerable = True
                else:
                    if operator_start:
                        try:
                            vulnerable_start = operator_start == ">=" and Version(product_version, suffix) >= Version(version_start, suffix)
                            vulnerable_start |= operator_start == ">" and Version(product_version, suffix) > Version(version_start, suffix)
                        except:
                            d.logger.warn(
                                "%s: Failed to compare %s %s %s for %s"
                                % (product_name, product_version, operator_start, version_start, cve)
                            )
                            vulnerable_start = False
                    else:
                        vulnerable_start = False

                    if operator_end:
                        try:
                            vulnerable_end = operator_end == "<=" and Version(product_version, suffix) <= Version(version_end, suffix)
                            vulnerable_end |= operator_end == "<" and Version(product_version, suffix) < Version(version_end, suffix)
                        except:
                            d.logger.warn(
                                "%s: Failed to compare %s %s %s for %s"
                                % (product_name, product_version, operator_end, version_end, cve)
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
                        d.logger.debug("%s is ignored in %s-%s" % (cve, package_name, real_pv))
                        Database.cve_update(d, cve_data, cve, {"abbrev-status": "Ignored"})
                    else:
                        d.logger.debug("%s-%s is vulnerable to %s" % (package_name, real_pv, cve))
                        Database.cve_update(
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
                d.logger.debug("%s-%s is not vulnerable to %s" % (package_name, real_pv, cve))
                Database.cve_update(
                    d,
                    cve_data,
                    cve,
                    {"abbrev-status": "Patched", "status": "version-not-in-range"},
                )
        cve_cursor.close()

    def get_cve_info(self, d, cve_data :dict):
        """
        Modifies and enriches the provided cve_data dict, with the data from the Database
        Args:
            d (CheckerConfig): for logging reasons
            cve_data (dict): in and out parameter containing cve_data list of considered CVE's

        Returns:
            dict: of enriched cve_data
        """

        for cve in cve_data:
            cursor = self.conn.execute("SELECT * FROM NVD WHERE ID IS ?", (cve,))
            for row in cursor:
                # The CVE itself has been added already
                if row[0] not in cve_data:
                    #@TODO: Fix logger!
                    d.logger.info("CVE record %s not present" % row[0])
                    continue

                cve_data[row[0]]["NVD-summary"] = row[1]
                cve_data[row[0]]["NVD-scorev2"] = row[2]
                cve_data[row[0]]["NVD-scorev3"] = row[3]
                cve_data[row[0]]["NVD-modified"] = row[4]
                cve_data[row[0]]["NVD-vector"] = row[5]
                cve_data[row[0]]["NVD-vectorString"] = row[6]
            cursor.close()

    # Helper function
    @staticmethod
    def __cve_is_status(cve_data, cve, status):
        if cve not in cve_data:
            return False
        if "abbrev-status" not in cve_data[cve]:
            return False
        if cve_data[cve]["abbrev-status"] == status:
            return True
        return False

    @staticmethod
    def __cve_is_ignored(cve_data, cve):
        return NVDDatabase.__cve_is_status(cve_data, cve, "Ignored")

    @staticmethod
    def __cve_is_patched(cve_data, cve):
        return NVDDatabase.__cve_is_status(cve_data, cve, "Patched")

    def close(self):
        self.conn.close()

