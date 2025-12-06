import re


def sanitize_sql_string(input_string):
    sanitized = re.sub(r"[\'\";\\\x00\-\x1F\x7F]", "", input_string)

    sanitized = re.sub(
        r"\/\*.*?\*\/|--.*?$", "", sanitized, flags=re.MULTILINE | re.DOTALL
    )

    dangerous_patterns = [
        r"\b(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+|\bUNION\s+SELECT\b|\bOR\s+['1]?=)",
        r"\b(SELECT\s+\*|EXEC(\s+\(|\()|XP_|sp_|ALTER\s+TABLE)",
        r"\b(GRANT|REVOKE|SHUTDOWN|CREATE\s+(TABLE|USER|DATABASE))",
    ]

    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

    sanitized = re.sub(r"\s+", " ", sanitized).strip()

    return sanitized
