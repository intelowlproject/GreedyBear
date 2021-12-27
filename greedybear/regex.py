# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
REGEX_CVE_URL = r"//[a-zA-Z\d_-]{1,200}(?:\.[a-zA-Z\d_-]{1,200})+(?::\d{2,6})?(?:/[a-zA-Z\d_=-]{1,200})*(?:\.\w+)?"
REGEX_CVE_BASE64COMMAND = "/Command/Base64/((?:[a-zA-Z\+\/\d]+)(?:={0,3}))}"
REGEX_URL = REGEX_CVE_URL[2:]
REGEX_URL_PROTOCOL = r"(?:htt|ft|tc|lda)ps?" + REGEX_CVE_URL
