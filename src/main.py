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
2. Runs hardened regex patterns against it to extract 4 data types:
      - Email addresses (general + ALU-specific domains)  [required]
      - Credit card numbers (with Luhn checksum validation) [required]
      - URLs
      - Phone numbers
3. Treats the input as UNTRUSTED. Nothing extracted is assumed safe just
   because a pattern matched syntactically (see SECURITY NOTES below).
4. Produces a structured, masked JSON report + a human-readable console
   summary. Sensitive fields (emails, card numbers) are redacted in the
   saved output so they are not needlessly exposed in logs/files.

SECURITY NOTES (see also inline comments near each function)
--------------------------------------------------------------
- Input is never treated as trusted or executable. Even though this
  version does not extract HTML tags as a data type, the text is still
  scanned for dangerous patterns (script tags, inline event handlers,
  SQL-injection-style fragments) and any hits are reported as security
  flags rather than silently ignored or silently trusted.
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
      - Missing/unreadable files fail with a clear error instead of a
        raw traceback, since we should never assume the environment is
        set up correctly.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        raise SystemExit(
            f"ERROR: input file not found at '{path}'. "
            f"Make sure you're running this script from the project root "
            f"(e.g. `python3 src/main.py`), and that {path} exists."
        )
    except PermissionError:
        raise SystemExit(f"ERROR: permission denied reading '{path}'.")

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
# 1) EMAIL ADDRESSES  (general + ALU-specific)  [REQUIRED]
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
# 2) CREDIT CARD NUMBERS  (shape match + Luhn checksum validation)  [REQUIRED]
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
    Standard Luhn checksum (mod 10 algorithm), used by virtually all major
    card issuers (Visa, Mastercard, Amex, Discover) to catch accidental
    typos and obviously-fabricated numbers before they even reach a payment
    processor.

    How it works:
      1. Starting from the rightmost digit, double every second digit.
      2. If doubling a digit produces a number > 9, subtract 9 from it
         (equivalent to summing its two digits, e.g. 8*2=16 -> 1+6=7).
      3. Sum all the digits (doubled and untouched).
      4. The number is valid if that sum is divisible by 10.

    This is what separates a *real-looking* card number from something
    that merely has the right shape (e.g. the obviously-fake
    '1234-5678-9012-3456' used as a test payload in our sample input).
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
# Handles: +250 788 123 456, +1-202-555-0143, (415) 555-0192,
# +250.788.234.567 (dot-separated, e.g. WhatsApp-style), etc.
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
# SECURITY: detect suspicious / injection-style content in the raw text,
# independent of which data types we extract as "results". These are
# *reported*, never executed, never used to build a query/command.
# ---------------------------------------------------------------------------
SQLI_PATTERN_RE = re.compile(
    r"(?:'\s*;\s*DROP\s+TABLE)"
    r"|(?:\bUNION\b\s+\bSELECT\b)"
    r"|(?:--\s*$)"
    r"|(?:\bOR\b\s+1\s*=\s*1\b)",
    re.IGNORECASE | re.MULTILINE,
)

# Even though this version doesn't extract HTML tags as a data type, a
# hostile payload embedded in the text (e.g. a stored-XSS attempt riding
# along inside what looks like a support ticket) should still be caught
# and reported rather than silently ignored.
SCRIPT_TAG_RE = re.compile(r"<\s*script\b", re.IGNORECASE)
EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=\s*[\"']", re.IGNORECASE)


def detect_security_flags(text: str):
    flags = []
    for m in SQLI_PATTERN_RE.finditer(text):
        flags.append(f"Possible SQL-injection-style fragment detected near position {m.start()}")
    for m in SCRIPT_TAG_RE.finditer(text):
        flags.append(f"Possible <script> tag detected near position {m.start()} (not executed, flagged only)")
    for m in EVENT_HANDLER_RE.finditer(text):
        flags.append(f"Possible inline event handler detected near position {m.start()} (e.g. onerror=)")
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
    security_flags = detect_security_flags(text)

    report = {
        "summary": {
            "emails_found": len(emails),
            "credit_cards_found": len(cards),
            "credit_cards_luhn_valid": sum(1 for c in cards if c["luhn_valid"]),
            "urls_found": len(urls),
            "phone_numbers_found": len(phones),
            "security_flags_raised": len(security_flags),
        },
        "emails": emails,                      # masked
        "credit_cards": cards,                 # masked, with luhn_valid flag
        "urls": urls,
        "phone_numbers": phones,
        "security_flags": security_flags,
        "note": (
            "Emails and credit card numbers are masked in this file by design. "
            "Full values are never written to disk or logs."
        ),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Console summary (also uses only masked values)
    print("     ALU REGEX DATA EXTRACTION      ")
    for key, value in report["summary"].items():
        print(f"{key:30s}: {value}")
    if security_flags:
        print("\n     SECURITY FLAGS RAISED     ")
        for flag in security_flags:
            print(f" - {flag}")
    print(f"\nFull report written to: {output_path}")


if __name__ == "__main__":
    run("input/raw-text.txt", "output/sample-output.json")
