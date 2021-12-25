REGEX_CVE_LOG4J = r"//[a-zA-Z\d_-]{1,200}(?:\.[a-zA-Z\d_-]{1,200})+(?::\d{2,6})?(?:/[a-zA-Z\d_=-]{1,200})*(?:\.\w+)?"
REGEX_CVE_BASE64COMMAND = "/Command/Base64/((?:[a-zA-Z\+\/\d]+)(?:={0,3}))}"
REGEX_URL = REGEX_CVE_LOG4J[2:]
