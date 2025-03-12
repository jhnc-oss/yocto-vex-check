from abc import abstractmethod
import re
from enum import Enum


class versionType(Enum):
    GIT = 'git'
    CUSTOM = 'custom'
    SEMANTIC = 'semver'
    UNKNOWN = 'unknown'




class BaseCustomVersion:

    def __init__(self, version: str):
        self.version :str = version
        if not self.is_version(self.version):
            raise ValueError("Version string does not match the Semantic Versioning pattern")

    @staticmethod
    @abstractmethod
    def is_version(version :str):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __le__(self, other):
        pass

    @abstractmethod
    def __lt__(self, other):
        pass

    @abstractmethod
    def __gt__(self, other):
        pass

    @abstractmethod
    def __ge__(self, other):
        pass

class SemanticVersioning(BaseCustomVersion):

    def __init__(self, version: str):
        super().__init__(version)


    def __eq__(self, other):
        if not isinstance(other, SemanticVersioning):
            raise TypeError("Can't compare versions of different type!")
        self_parts = self.version.split(".")
        other_parts = other.version.split(".")

        # Add missing zeros if needed
        self.__normalize_semver(self_parts)
        self.__normalize_semver(other_parts)
        for i in range(3):
            # Special case - and *
            if other_parts[i] == "*" or other_parts[i] == "-":
                return False
            if int(self_parts[i]) != int(other_parts[i]):
                return False
        return True

    def __lt__(self, other):
        if not isinstance(other, SemanticVersioning):
            raise TypeError("Can't compare versions of different type!")

        # Special case, * means "no upper boundry"
        if other.version == "*":
            return True

        if self == other:
            return False

        self_parts = self.version.split(".")
        other_parts = other.version.split(".")

        # Add missing zeros if needed
        self.__normalize_semver(self_parts)
        self.__normalize_semver(other_parts)
        for i in range(3):
            if other_parts[i] == "*":
                return True
            elif int(self_parts[i]) != int(other_parts[i]):
                return int(self_parts[i]) < int(other_parts[i])
        return False

    def __le__(self, other):
        if not isinstance(other, SemanticVersioning):
            raise TypeError("Can't compare versions of different type!")
        if self == other:
            return True
        if self < other:
            return True
        return False

    def __ge__(self, other):
        if not isinstance(other, SemanticVersioning):
            raise TypeError("Can't compare versions of different type!")

        # Special case, - means "all", 0 means "first available", * means "no upper boundry"
        if self.version == "-" or self.version == "*" or self.version == "0":
            return True

        if self == other:
            return True

        return  self > other


    def __gt__(self, other):
        if not isinstance(other, SemanticVersioning):
            raise TypeError("Can't compare versions of different type!")

        # Special case, - means "all", 0 means "first available", * means "no upper boundry"
        if other.version == "-" or other.version == "*" or other.version == "0":
            return True

        self_parts = self.version.split(".")
        other_parts = other.version.split(".")

        # Add missing zeros if needed
        self.__normalize_semver(self_parts)
        self.__normalize_semver(other_parts)

        for i in range(3):
            # * means "no upper boundry"
            if other_parts[i] == "*":
                return True
            elif int(self_parts[i]) != int(other_parts[i]):
                return int(self_parts[i]) > int(other_parts[i])
        return False

    @staticmethod
    def is_version(version :str):
        semver_pattern = r"^(\d+(\.\d+){0,2}|-|0|(\d\.){0,2}(\*))$"
        if version == "unspecified":
            return True
        if version == "0":
            return True
        if version == "-":
            return True

        # Special case, * can be used in "lessThan" attribute to denote a range with no upper bound at all
        if version == "*":
            return True
        if re.match(semver_pattern, version):
            return True
        return False

    @staticmethod
    def __normalize_semver(version :list[str]):
        """ Process a parsed (split) semver. Add zeros if the version has  less than three digits"""
        while len(version) < 3:
            version.append(0)


class OpenSSLVersioning(BaseCustomVersion):

    def __init__(self, version :str):
        super().__init__(version)

    def __eq__(self, other):
        if not isinstance(other, OpenSSLVersioning):
            raise TypeError("Can't compare versions of different type!")
        # get Version Tuples and compare them!
        v = self.__normalize_open_ssl(self.version)
        t = self.__normalize_open_ssl(other.version)
        return v == t

    def __lt__(self, other):
        if not isinstance(other, OpenSSLVersioning):
            raise TypeError("Can't compare versions of different type!")
        v = self.__normalize_open_ssl(self.version)
        t = self.__normalize_open_ssl(other.version)
        return v < t

    def __le__(self, other):
        if not isinstance(other, OpenSSLVersioning):
            raise TypeError("Can't compare versions of different type!")
        v = self.__normalize_open_ssl(self.version)
        t = self.__normalize_open_ssl(other.version)
        return v <= t

    def __ge__(self, other):
        if not isinstance(other, OpenSSLVersioning):
            raise TypeError("Can't compare versions of different type!")
        v = self.__normalize_open_ssl(self.version)
        t = self.__normalize_open_ssl(other.version)
        return v >= t


    def __gt__(self, other):
        if not isinstance(other, OpenSSLVersioning):
            raise TypeError("Can't compare versions of different type!")
        v = self.__normalize_open_ssl(self.version)
        t = self.__normalize_open_ssl(other.version)
        return v > t

    @staticmethod
    def is_version(version :str):
        openssl_pattern = r"^\d+(\.\d+)*[a-z]*(-dev)?$"
        if re.match(openssl_pattern, version):
            return True
        return False

    def __normalize_open_ssl(self, version :str):
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


def versions_factory(veriosn_str :str) -> BaseCustomVersion:

    # Loop through all subclasses of AbstractBaseClass and instantiate them
    for Version in BaseCustomVersion.__subclasses__():
        if Version.is_version(veriosn_str):
            return Version(veriosn_str)
    return None