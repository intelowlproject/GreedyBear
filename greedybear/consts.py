# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
SCANNER = "scanner"
PAYLOAD_REQUEST = "payload_request"

GET = "GET"
POST = "POST"

FEEDS_LICENSE = "https://github.com/honeynet/GreedyBear/blob/main/FEEDS_LICENSE.md"

REGEX_DOMAIN = r"^[a-zA-Z\d-]{1,60}(\.[a-zA-Z\d-]{1,60})*$"
REGEX_IP = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
REGEX_PASSWORD = r"^[a-zA-Z0-9]{12,}$"

DOMAIN = "domain"
IP = "ip"

REQUIRED_FIELDS = [
    "@timestamp",
    "src_ip",
    "dest_port",
    "ip_rep",
    "geoip",
    "deobfuscated_payload",
    "correlation_id",
    "url",
    "message",
    "reason",
    "correlation_id",
    "eventid",
    "session",
    "timestamp",
    "duration",
    "username",
    "password",
    "t-pot_ip_ext",
]
