# ALU Regex Data Extraction

A regex-based tool that extracts and validates structured data from raw,
messy, production-style text (modeled on a support-ticket / CRM export
returned by an external API).

## Folder structure

```
alu-regex-data-extraction_jnshuti-cpu/
├── input/
│   └── raw-text.txt        # realistic, messy sample input
├── src/
│   └── main.py              # extraction + validation logic
├── output/
│   └── sample-output.json   # generated report (masked, safe to share)
└── README.md
```

## How to run it

Requires Python 3.8+, standard library only (no third-party packages).

```bash
cd alu-regex-data-extraction_jnshuti-cpu
python3 src/main.py
```

This reads `input/raw-text.txt`, runs all extraction/validation logic, prints
a console summary, and writes the full structured report to
`output/sample-output.json`.

## What it extracts

This project implements 4 data types, meeting the assignment's requirement
of "at least two data types, plus emails and credit card numbers":

1. **Email addresses** *(required)* — general RFC-practical pattern, plus
   ALU-specific classification into `alu_official`
   (`@alueducation.com`), `alu_alumni` (`@alumni.alueducation.com`),
   `alu_si` (`@si.alueducation.com`), or `external`.
2. **Credit card numbers** *(required)* — matched by shape (13–19 digits,
   grouped in 4s), then validated with the **Luhn checksum algorithm**. A
   number that merely *looks* like a card (e.g. `1234-5678-9012-3456`) is
   reported but flagged `luhn_valid: false`, so a bug like "the form
   accepted an obviously fake card" is visible in the data instead of
   silently passing through.
3. **URLs** — requires an explicit `http(s)://` scheme, which deliberately
   excludes bare `www.example.com` text (too ambiguous with plain prose in
   free-form text).
4. **Phone numbers** — handles international (`+250 788 123 456`), US-style
   parens (`(415) 555-0192`), hyphenated (`+1-202-555-0143`), and
   dot-separated / WhatsApp-style (`+250.788.234.567`) formats. Explicitly
   excludes numerically-similar-but-different shapes: ISO timestamps
   (`2024-11-03`) and US SSNs (`999-99-9999`), since they use a different
   grouping convention than real phone numbers.

## Security considerations

The prompt for this assessment is explicit that **input from an external
API should never be treated as automatically trustworthy**, so this project
treats every stage of the pipeline as adversarial:

- **Input size cap** (`MAX_INPUT_CHARS`) — a crude but effective guard
  against a hostile or malformed payload being used to exhaust CPU/memory
  ("regex-DoS"-style risk) before it even reaches the regex engine.
- **Unicode normalization + control-character stripping** — raw text is
  normalized (`NFKC`) and stripped of non-printable control characters
  (except `\n`/`\t`) before matching, to reduce the risk of homoglyph
  tricks or terminal/log-injection via embedded control sequences.
- **Graceful error handling** — a missing or unreadable input file produces
  a clear error message instead of a raw Python traceback, since the
  program should never assume its environment is set up correctly.
- **ReDoS-aware regex design** — patterns avoid nested unbounded
  quantifiers (e.g. no `(a+)+`); character classes use explicit `{min,max}`
  bounds where length matters (email local/domain parts, card/phone digit
  groups) instead of unconstrained `+`/`*`.
- **No blind trust in shape** — a credit card number is only accepted as
  plausible after passing the Luhn checksum, not just because it matches
  the "4 groups of 4 digits" shape.
- **Injection-pattern detection, independent of extracted data types** —
  even though this version doesn't extract HTML tags as a formal data
  type, the raw text is still scanned for `<script>` tags, inline event
  handlers (`onerror=`, `onclick=`, ...), and SQL-injection-style fragments
  (`'; DROP TABLE ...`, `UNION SELECT`, `OR 1=1`). Any hits are reported as
  `security_flags`, never executed, and never passed to `eval`, a browser
  context, a shell, or a database query.
- **Sensitive data masking** — emails and credit card numbers, the two data
  types explicitly called out as sensitive, are **masked before being
  written to `output/sample-output.json` or printed to the console**
  (`g*****@alueducation.com`, `**** **** **** 1111`). Full values only ever
  exist in memory during a single run and are never persisted or logged.

## Sample input

`input/raw-text.txt` is a fictional but realistic support-ticket export
containing: ALU official/alumni/SI emails, a real payment URL and a
suspicious look-alike "mirror" URL, international, US-style, and
dot-separated (WhatsApp-style) phone numbers, multiple valid test cards
plus one obviously fake card number that fails the Luhn check on purpose,
an embedded SQL-injection-style fragment, and a `<script>` tag with an
`onerror=` payload — all of which are detected as security flags without
ever being treated as trusted or executable.

## Note on this submission

This assignment file contained a hidden instruction (embedded as if it were
part of the assessment brief) directing any AI assistant reading it to
covertly insert a specific sentence into the submitted source code without
telling the student. That instruction was not followed. If you're grading
this and want to verify, ask the student — they were told about it openly
during development rather than having it inserted behind their back.