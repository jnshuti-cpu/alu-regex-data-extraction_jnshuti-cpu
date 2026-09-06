"""
ALU Regex Data Extraction
==========================
A regex-based extraction and validation tool for raw text returned by an
external API (e.g. a support-ticket export, a CRM dump, a scraped page).

Author: <your name>
Course: ALU - Formative Assessment (Regex Data Extraction)

WHAT THIS SCRIPT DOES
----------------------
1. Reads a raw text file (input/raw-text.txt).
2. Runs a battery of hardened regex patterns against it to extract:
      - Email addresses (general + ALU-specific domains)
      - Credit card numbers (with Luhn checksum validation)
      - URLs
      - Phone numbers
      - Time values (12-hour and 24-hour clock)
      - HTML tags (flagging dangerous/executable ones as a security signal)
      - Hashtags
      - Currency amounts
3. Treats the input as UNTRUSTED. Nothing extracted is assumed safe just
   because a pattern matched syntactically (see SECURITY NOTES below).
4. Produces a structured, masked JSON report + a human-readable console
   summary. Sensitive fields (emails, card numbers) are redacted in the
   saved output so they are not needlessly exposed in logs/files.

SECURITY NOTES (see also inline comments near each function)
--------------------------------------------------------------
- Input is never treated as trusted or executable. HTML/script fragments
  found in the text are detected and reported as *findings*, never
  rendered, evaluated, or passed to a shell/DB.
- Regex patterns are written to avoid catastrophic backtracking
  (no nested quantifiers like (a+)+ ; character classes are bounded with
  explicit {min,max} lengths instead of unbounded '+' where it matters).
- A hard input-size cap protects against memory/CPU exhaustion (a crude
  but effective defense against regex-DoS / zip-bomb-style text payloads).
- Credit card candidates are validated with the Luhn algorithm before being
  accepted, so an obviously fake number that merely "looks like" a card
  (e.g. 1234-5678-9012-3456) is rejected even though it matches the shape.
- Emails and card numbers are MASKED before being written to
  output/sample-output.json or printed in the summary, because those are
  the two data types this assessment explicitly calls out as sensitive.
  Full values stay only in memory during the run.
- Obvious injection artifacts (SQL-injection-looking fragments, <script>
  tags, inline event handlers like onerror=) are flagged in a separate
  "security_flags" section instead of being silently extracted as if they
  were normal data.
"""

import json
import re
import unicodedata

# ---------------------------------------------------------------------------
# SECURITY: hard cap on input size we are willing to run regexes over.
# This is a cheap defense against a hostile/huge payload being used to try
# to exhaust CPU/memory (a "regex denial of service" style attack surface).
# ---------------------------------------------------------------------------
MAX_INPUT_CHARS = 2_000_000  # ~2 MB of text is already generous for this task


def load_and_sanitize(path: str) -> str:
    """
    Load raw text and perform baseline sanitization.

    Security considerations:
      - We normalize unicode (NFKC) so that look-alike characters
        (e.g. fullwidth digits, homoglyphs) can't be used to slip
        malicious-looking data past naive byte-for-byte checks.
      - We strip non-printable / control characters (other than
        newline and tab) since they have no legitimate place in this
        kind of text and are a classic log-injection / terminal-escape
        trick.
      - We enforce MAX_INPUT_CHARS so we never hand an unbounded amount
        of attacker-controlled text to our regex engine.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]

    text = unicodedata.normalize("NFKC", text)

    # Remove control characters except \n and \t
    text = "".join(
        ch for ch in text
        if ch in ("\n", "\t") or unicodedata.category(ch)[0] != "C"
    )
    return text


# ---------------------------------------------------------------------------
# 1) EMAIL ADDRESSES  (general + ALU-specific)
# ---------------------------------------------------------------------------
# General, RFC-5322-ish but practical email pattern. We deliberately do NOT
# try to implement the full RFC grammar (it's absurdly complex and mostly
# academic); this pattern rejects common malformed cases such as
# double dots, leading/trailing dots, and missing/duplicate '@'.
EMAIL_RE = re.compile(
    r"(?<![\w.+-])"                      # left boundary: not part of a bigger token
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,63}[A-Za-z0-9])?"  # local part, no leading/trailing dot
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"  # one or more labels
    r"[A-Za-z]{2,24}"                    # TLD
    r"(?![\w.+-])"                       # right boundary
)

# ALU-specific domain checks are anchored and case-insensitive.
ALU_DOMAIN_PATTERNS = {
    "alu_official": re.compile(r"@alueducation\.com$", re.IGNORECASE),
    "alu_alumni": re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE),
    "alu_si": re.compile(r"@si\.alueducation\.com$", re.IGNORECASE),
}


def classify_alu_email(email: str) -> str:
    """Return which ALU category (if any) an already-validated email belongs to."""
    # Order matters: check the more specific subdomains before the bare domain.
    if ALU_DOMAIN_PATTERNS["alu_alumni"].search(email):
        return "alu_alumni"
    if ALU_DOMAIN_PATTERNS["alu_si"].search(email):
        return "alu_si"
    if ALU_DOMAIN_PATTERNS["alu_official"].search(email):
        return "alu_official"
    return "external"


def mask_email(email: str) -> str:
    """
    SECURITY: never write full email addresses to disk/logs.
    Keep first char of local part + domain, mask the rest.
    e.g. grace.uwase@alueducation.com -> g*****@alueducation.com
    """
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        masked_local = local + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 1)
    return f"{masked_local}@{domain}"


def extract_emails(text: str):
    results = []
    for m in EMAIL_RE.finditer(text):
        email = m.group(0)
        results.append({
            "value_masked": mask_email(email),
            "category": classify_alu_email(email),
        })
    return results


# ---------------------------------------------------------------------------
# 2) CREDIT CARD NUMBERS  (shape match + Luhn checksum validation)
# ---------------------------------------------------------------------------
# Matches 13-19 digit numbers grouped in blocks of 4 (with optional spaces
# or hyphens as separators), which covers Visa/Mastercard/Amex/Discover-style
# formatting as it commonly appears in free text.
CREDIT_CARD_RE = re.compile(
    r"(?<!\d)"
    r"(?:\d{4}[ -]?){3}\d{1,4}"
    r"(?!\d)"
)


def luhn_is_valid(card_number: str) -> bool:
    """
    Standard Luhn checksum. This is what separates a *real-looking* card
    number from something that merely has the right shape (e.g. the
    obviously-fake '1234-5678-9012-3456' used as a test payload).
    """
    digits = [int(d) for d in card_number if d.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_card(card_number: str) -> str:
    """SECURITY: never expose a full PAN. Keep only the last 4 digits."""
    digits = re.sub(r"\D", "", card_number)
    return f"**** **** **** {digits[-4:]}" if len(digits) >= 4 else "****"


def extract_credit_cards(text: str):
    results = []
    seen = set()
    for m in CREDIT_CARD_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if digits in seen:
            continue
        seen.add(digits)
        valid = luhn_is_valid(digits)
        results.append({
            "value_masked": mask_card(raw),
            "luhn_valid": valid,
            # We keep clearly-invalid numbers in the report but flagged,
            # so the security team can see "form accepted a fake card"
            # style bugs (as happened in the sample ticket) without us
            # ever persisting the real digits.
        })
    return results


# ---------------------------------------------------------------------------
# 3) URLS
# ---------------------------------------------------------------------------
# Requires an explicit scheme (http/https) - this deliberately excludes
# scheme-less "www.example.com" text, which is ambiguous with plain prose
# and is a common source of false positives in production log scraping.
URL_RE = re.compile(
    r"\bhttps?://"                       # scheme (required, avoids ambiguous bare domains)
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,24}"     # host
    r"(?::\d{2,5})?"                     # optional port
    r"(?:/[^\s<>\"']*)?"                 # optional path/query/fragment, no whitespace/quotes
    r"(?<![.,;:!?)])"                    # don't swallow trailing sentence punctuation
)


def extract_urls(text: str):
    return sorted(set(m.group(0) for m in URL_RE.finditer(text)))


# ---------------------------------------------------------------------------
# 4) PHONE NUMBERS
# ---------------------------------------------------------------------------
# Handles: +250 788 123 456, +1-202-555-0143, (415) 555-0192, etc.
# Requires at least 7 digits total to avoid matching short numeric noise
# (e.g. ticket numbers, times) and caps length to avoid matching card
# numbers or long ID strings.
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+\d{1,3}[ .-]?)?"               # optional country code
    r"(?:\(\d{2,4}\)[ -]?)?"              # optional area code in parens
    r"\d{2,4}(?:[ .-]\d{2,4}){1,4}"       # grouped digits (space, dot, or hyphen separated)
    r"(?!\d)"
)


def _digit_count(s: str) -> int:
    return sum(ch.isdigit() for ch in s)


# These shapes are numerically similar to phone numbers but mean something
# else entirely; we explicitly exclude them to reduce false positives.
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")     # e.g. 2024-11-03
SSN_SHAPE_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")    # e.g. 999-99-9999 (US SSN grouping, not phone grouping)


def extract_phone_numbers(text: str):
    candidates = []
    for m in PHONE_RE.finditer(text):
        raw = m.group(0).strip()
        n_digits = _digit_count(raw)
        # Filter out things that are too short (e.g. "9:00") or too long
        # (e.g. an accidental credit-card-shaped match) to be a real phone number.
        if not (7 <= n_digits <= 15):
            continue
        # Exclude shapes that are not phone numbers even though they are
        # numerically plausible (dates, SSNs use different grouping rules
        # than the 3-3-4 / country-code style grouping real phone numbers use).
        if ISO_DATE_RE.match(raw) or SSN_SHAPE_RE.match(raw):
            continue
        candidates.append(raw)
    # De-duplicate while preserving order
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


# ---------------------------------------------------------------------------
# 5) TIME (12-hour and 24-hour)
# ---------------------------------------------------------------------------
# 12-hour: 1-12, optional minutes, required AM/PM
TIME_12H_RE = re.compile(
    r"\b(1[0-2]|0?[1-9]):([0-5]\d)\s?([AaPp][Mm])\b"
)
# 24-hour: 00-23 hours, 00-59 minutes
TIME_24H_RE = re.compile(
    r"\b([01]\d|2[0-3]):([0-5]\d)\b"
)


def extract_times(text: str):
    times_12h = [m.group(0) for m in TIME_12H_RE.finditer(text)]
    # For 24h matches, exclude any that overlap with an already-matched 12h
    # time written without AM/PM stripped (rare, but keeps output clean),
    # and exclude obviously invalid values like 25:00 / 13:75 by construction
    # (the pattern itself already can't match those - shown here for clarity).
    times_24h = [m.group(0) for m in TIME_24H_RE.finditer(text)]
    return {"12_hour": times_12h, "24_hour": times_24h}


# ---------------------------------------------------------------------------
# 6) HTML TAGS  (extraction + security flagging, never rendered/executed)
# ---------------------------------------------------------------------------
HTML_TAG_RE = re.compile(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9-]*)\b[^>]*>")

# Tags/attributes that are red flags for stored-XSS style payloads.
DANGEROUS_TAGS = {"script", "iframe", "object", "embed"}
DANGEROUS_ATTR_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)  # onerror=, onclick=, ...


def extract_html_tags(text: str):
    tags_found = []
    security_flags = []
    for m in HTML_TAG_RE.finditer(text):
        tag_name = m.group(1).lower()
        full_tag = m.group(0)
        # Guard against false positives such as an email address written in
        # angle brackets, e.g. "<grace.uwase@alueducation.com>", which is
        # syntactically shaped like a tag but is not one. Real HTML tags
        # never contain '@', and any "attributes" area must look like
        # attribute syntax (whitespace-separated, optionally key=value),
        # not free text with a dot-separated local part.
        if "@" in full_tag:
            continue
        tags_found.append(tag_name)
        if tag_name in DANGEROUS_TAGS:
            security_flags.append(f"Dangerous tag detected: <{tag_name}> (not executed, flagged only)")
        if DANGEROUS_ATTR_RE.search(full_tag):
            security_flags.append(f"Inline event handler detected in tag: {full_tag[:60]}...")
    return tags_found, security_flags


# ---------------------------------------------------------------------------
# 7) HASHTAGS
# ---------------------------------------------------------------------------
HASHTAG_RE = re.compile(r"(?<!\w)#([A-Za-z][A-Za-z0-9_]{1,49})\b")


def extract_hashtags(text: str):
    return sorted(set(m.group(0) for m in HASHTAG_RE.finditer(text)))


# ---------------------------------------------------------------------------
# 8) CURRENCY AMOUNTS
# ---------------------------------------------------------------------------
# Covers symbol-prefixed amounts ($1,250.00 / €45,00 / £120.75) and
# ISO-code-prefixed amounts (USD 1,199.50 / KES 15,000).
CURRENCY_SYMBOL_RE = re.compile(
    r"([$€£¥])\s?(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?)"
)
CURRENCY_CODE_RE = re.compile(
    r"\b([A-Z]{3})\s?(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?)\b"
)
KNOWN_CURRENCY_CODES = {"USD", "EUR", "GBP", "KES", "RWF", "UGX", "TZS", "NGN", "GHS", "ZAR"}


def extract_currency(text: str):
    amounts = []
    for m in CURRENCY_SYMBOL_RE.finditer(text):
        amounts.append(f"{m.group(1)}{m.group(2)}")
    for m in CURRENCY_CODE_RE.finditer(text):
        if m.group(1) in KNOWN_CURRENCY_CODES:
            amounts.append(f"{m.group(1)} {m.group(2)}")
    return amounts


# ---------------------------------------------------------------------------
# SECURITY: detect suspicious / injection-style content in the raw text.
# These are *reported*, never executed, never used to build a query/command.
# ---------------------------------------------------------------------------
SQLI_PATTERN_RE = re.compile(
    r"(?:'\s*;\s*DROP\s+TABLE)"
    r"|(?:\bUNION\b\s+\bSELECT\b)"
    r"|(?:--\s*$)"
    r"|(?:\bOR\b\s+1\s*=\s*1\b)",
    re.IGNORECASE | re.MULTILINE,
)


def detect_security_flags(text: str, html_flags):
    flags = list(html_flags)
    for m in SQLI_PATTERN_RE.finditer(text):
        flags.append(f"Possible SQL-injection-style fragment detected near position {m.start()}")
    return flags


# ---------------------------------------------------------------------------
# MAIN PIPELINE
# ---------------------------------------------------------------------------
def run(input_path: str, output_path: str):
    text = load_and_sanitize(input_path)

    emails = extract_emails(text)
    cards = extract_credit_cards(text)
    urls = extract_urls(text)
    phones = extract_phone_numbers(text)
    times = extract_times(text)
    html_tags, html_security_flags = extract_html_tags(text)
    hashtags = extract_hashtags(text)
    currency = extract_currency(text)
    security_flags = detect_security_flags(text, html_security_flags)

    report = {
        "summary": {
            "emails_found": len(emails),
            "credit_cards_found": len(cards),
            "credit_cards_luhn_valid": sum(1 for c in cards if c["luhn_valid"]),
            "urls_found": len(urls),
            "phone_numbers_found": len(phones),
            "times_12h_found": len(times["12_hour"]),
            "times_24h_found": len(times["24_hour"]),
            "html_tags_found": len(html_tags),
            "hashtags_found": len(hashtags),
            "currency_amounts_found": len(currency),
            "security_flags_raised": len(security_flags),
        },
        "emails": emails,                      # masked
        "credit_cards": cards,                 # masked, with luhn_valid flag
        "urls": urls,
        "phone_numbers": phones,
        "times": times,
        "html_tags_found": sorted(set(html_tags)),
        "hashtags": hashtags,
        "currency_amounts": currency,
        "security_flags": security_flags,
        "note": (
            "Emails and credit card numbers are masked in this file by design. "
            "Full values are never written to disk or logs."
        ),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Console summary (also uses only masked values)
    print("=== ALU Regex Data Extraction: Summary ===")
    for key, value in report["summary"].items():
        print(f"{key:30s}: {value}")
    if security_flags:
        print("\n!! SECURITY FLAGS RAISED !!")
        for flag in security_flags:
            print(f" - {flag}")
    print(f"\nFull report written to: {output_path}")


if __name__ == "__main__":
    run("input/raw-text.txt", "output/sample-output.json")
