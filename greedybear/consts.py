# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
SCANNER = "scanner"
PAYLOAD_REQUEST = "payload_request"

# List of Honeypots from which only source IP of attacker is extracted - case sensitive naming
GENERAL_HONEYPOTS = [
    "Heralding",
    "Ciscoasa",
    "Honeytrap",
    "Dionaea",
    "ConPot",
    "Adbhoney",
    "Tanner",
    "CitrixHoneypot",
    "Mailoney",
    "Ipphoney",
    "Ddospot",
    "ElasticPot",
    "Dicompot",
    "Redishoneypot",
    "Sentrypeer",
]

GET = "GET"
POST = "POST"

FEEDS_LICENSE = "https://github.com/honeynet/GreedyBear/blob/main/FEEDS_LICENSE.md"

REGEX_DOMAIN = r"^[a-zA-Z\d-]{1,60}(\.[a-zA-Z\d-]{1,60})*$"
REGEX_IP = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"

DOMAIN = "domain"
IP = "ip"
