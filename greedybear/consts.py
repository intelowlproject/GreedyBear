# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
SCANNER = "scanner"
PAYLOAD_REQUEST = "payload_request"

GET = "GET"
POST = "POST"

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


# API consist of news list.
GITHUB_BLOG_API = "https://api.github.com/repos/intelowlproject/intelowlproject.github.io/contents/Blogs"

# location of the full blog that are hosted in web
BLOG_BASE_URL = "https://intelowlproject.github.io/blogs"

# cache key used for news
CACHE_KEY_GREEDYBEAR_NEWS = "greedybear_news"

# we leverage a 1-hour caching strategy to stay within GitHub’s 60 req/hr API constraints.
# Also This optimization reduces average latency from approx 5–7 seconds down to a approx 162ms."
CACHE_TIMEOUT_SECONDS = 60 * 60

# [Optimization] Limit fetch size for blogs/data to:
# 1. Prevent in-memory cache bottlenecks.
# 2. Reduce network latency.
MAX_FILES_TO_CHECK = 30
