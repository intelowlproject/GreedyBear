EXCLUDED_PREFIXES = [
    "/api/auth/",
    "/api/me/",
    "/api/news/",
    "/api/statistics",
]


def preprocessing_filter_spec(endpoints):
    return [
        (path, path_regex, method, callback)
        for path, path_regex, method, callback in endpoints
        if not any(path.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
    ]
