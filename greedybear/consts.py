# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
SCANNER = "scanner"
PAYLOAD_REQUEST = "payload_request"

GET = "GET"
POST = "POST"

REGEX_DOMAIN = r"^[a-zA-Z\d-]{1,60}(\.[a-zA-Z\d-]{1,60})*$"
REGEX_IP = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
REGEX_PASSWORD = r"^(?=.*[a-zA-Z]).{12,}$"

DOMAIN = "domain"
IP = "ip"

REQUIRED_FIELDS = [
    "@timestamp",
    "src_ip",
    "dest_port",
    "ip_rep",
    "geoip",
    "url",
    "message",
    "eventid",
    "session",
    "timestamp",
    "duration",
    "username",
    "password",
    "t-pot_ip_ext",
]


# we used this const to implement news feature
RSS_FEED_URL = "https://intelowlproject.github.io/feed.xml"
CACHE_KEY_GREEDYBEAR_NEWS = "greedybear_news"
CACHE_TIMEOUT_SECONDS = 60 * 60
