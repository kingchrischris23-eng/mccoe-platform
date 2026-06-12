import re

APACHE_PATTERN = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status_code>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"union\s+select",
        r"\.\./",
        r"<script",
        r"or\s+1\s*=\s*1",
        r"';?\s*drop\s+table",
    )
]