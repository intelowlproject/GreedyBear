import enum


class FrontendPage(enum.Enum):
    REGISTER = "register"
    LOGIN = "login"


class IpReputation(enum.StrEnum):
    MASS_SCANNER = "mass scanner"
    TOR_EXIT_NODE = "tor exit node"
    KNOWN_ATTACKER = "known attacker"
