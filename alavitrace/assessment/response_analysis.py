import re
import html
from enum import Enum
from typing import Dict, Optional, Tuple, Any, List

class XssContext(Enum):
    """Context where reflected input was identified within an HTML response."""
    SCRIPT = "SCRIPT"
    ATTRIBUTE = "ATTRIBUTE"
    URL = "URL"
    STYLE = "STYLE"
    TEXT = "TEXT"
    NONE = "NONE"

# Database error signatures grouped by database engine
DATABASE_ERROR_SIGNATURES: Dict[str, List[str]] = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"valid mysql result",
        r"mysqli?_fetch",
        r"mysqli?_query",
        r"check the manual that corresponds to your (mysql|mariadb) server version"
    ],
    "PostgreSQL": [
        r"postgresql.*error",
        r"pg_query\(\)",
        r"syntax error at or near",
        r"pg_exec\(\)",
        r"valid postgresql result",
        r"psqlexception"
    ],
    "Microsoft SQL Server": [
        r"driver.*sql[\-\_\ ]*server",
        r"sqlexception",
        r"unclosed quotation mark after the character string",
        r"syntax error.*in query expression",
        r"microsoft ole db provider for odbc drivers"
    ],
    "SQLite": [
        r"sqlite3::query",
        r"sqlite_error",
        r"unrecognized token:",
        r"near \".*\": syntax error",
        r"sqliteexception"
    ],
    "Oracle": [
        r"ora-[0-9]{4,5}",
        r"oracle error",
        r"pl/sql.*error"
    ],
    "Generic SQL": [
        r"sql syntax.*error",
        r"odbc driver.*error",
        r"database error"
    ]
}

def detect_db_error(body: str) -> Optional[Dict[str, str]]:
    """
    Scans response text for database syntax and error signatures.
    Returns matched engine and signature if found, or None.
    """
    if not body:
        return None

    body_lower = body.lower()
    for engine, patterns in DATABASE_ERROR_SIGNATURES.items():
        for pat in patterns:
            match = re.search(pat, body_lower, re.IGNORECASE)
            if match:
                return {
                    "database": engine,
                    "matched_pattern": pat,
                    "matched_snippet": match.group(0)
                }
    return None

def detect_sqli_error_difference(baseline_body: str, test_body: str) -> Optional[Dict[str, str]]:
    """
    Determines whether a test mutation triggered a database error that was
    NOT present in the baseline response. Eliminates false positives from
    pages that inherently contain words like 'SQL' or preexisting error messages.
    """
    if not test_body:
        return None

    test_err = detect_db_error(test_body)
    if not test_err:
        return None

    # Verify that this same pattern was not already present in the baseline
    baseline_match = re.search(test_err["matched_pattern"], (baseline_body or "").lower(), re.IGNORECASE)
    if baseline_match:
        # Preexisting error in baseline; do not report as finding
        return None

    return test_err

def classify_xss_context(body: str, canary: str) -> Tuple[XssContext, bool]:
    """
    Determines the reflection context of a canary value in HTML.
    Returns a tuple: (XssContext, is_encoded).
    """
    if not body or not canary:
        return XssContext.NONE, False

    # Check for encoded canary
    encoded_canary = html.escape(canary)
    is_encoded = (encoded_canary != canary) and (encoded_canary in body and canary not in body)

    if canary not in body and not is_encoded:
        return XssContext.NONE, False

    search_target = encoded_canary if is_encoded else canary

    # 1. Check Script Context (<script>...canary...</script>)
    script_pattern = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
    for match in script_pattern.finditer(body):
        if search_target in match.group(1):
            return XssContext.SCRIPT, is_encoded

    # 2. Check Style Context (<style>...canary...</style>)
    style_pattern = re.compile(r"<style\b[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL)
    for match in style_pattern.finditer(body):
        if search_target in match.group(1):
            return XssContext.STYLE, is_encoded

    # 3. Check HTML Attribute Context (<tag ... attr="...canary..." ...>)
    # Regex matches inside an open tag: <tagname attr="...canary..." ...>
    tag_pattern = re.compile(r"<[a-zA-Z0-9_\-]+(?:\s+[^>]*)?>", re.DOTALL)
    for tag_match in tag_pattern.finditer(body):
        tag_str = tag_match.group(0)
        if search_target in tag_str:
            # Check if inside href or src
            url_attr_pattern = re.compile(r"(?:href|src|action)\s*=\s*['\"][^'\"]*" + re.escape(search_target), re.IGNORECASE)
            if url_attr_pattern.search(tag_str):
                return XssContext.URL, is_encoded
            return XssContext.ATTRIBUTE, is_encoded

    # 4. Fallback: Body text reflection (<p>...canary...</p> or outside tags)
    return XssContext.TEXT, is_encoded

def analyze_xss_reflection(baseline_body: str, test_body: str, canary: str) -> Optional[Dict[str, Any]]:
    """
    Verifies that a canary string was reflected into the response body
    and was not present in the baseline. Classifies reflection context.
    """
    if not test_body or not canary:
        return None

    # Canary must NOT exist in the baseline (verifies true input reflection)
    if canary in (baseline_body or ""):
        return None

    context, is_encoded = classify_xss_context(test_body, canary)
    if context == XssContext.NONE:
        return None

    return {
        "context": context.value,
        "is_encoded": is_encoded,
        "canary": canary
    }
