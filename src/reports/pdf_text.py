"""Normalize text for Helvetica/latin-1 PDF output."""

import unicodedata

_UNICODE_REPLACEMENTS = {
    "\u2014": "-",  # em dash
    "\u2013": "-",  # en dash
    "\u2212": "-",  # minus sign
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2026": "...",
    "\u2022": "*",
    "\u00b7": "*",
    "\u00a0": " ",
    "\u200b": "",
    "\ufeff": "",
}


def sanitize_pdf_text(text: str | None) -> str:
    """Replace unsupported Unicode and ensure latin-1-safe output for core PDF fonts."""
    if text is None:
        return ""
    cleaned = str(text)
    for old, new in _UNICODE_REPLACEMENTS.items():
        cleaned = cleaned.replace(old, new)

    normalized = unicodedata.normalize("NFKD", cleaned)
    safe_chars: list[str] = []
    for char in normalized:
        if unicodedata.combining(char):
            continue
        try:
            char.encode("latin-1")
            safe_chars.append(char)
        except UnicodeEncodeError:
            safe_chars.append("?")
    return "".join(safe_chars)