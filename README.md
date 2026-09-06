# ALU Regex Data Extraction

A regex-based tool that extracts and validates structured data from raw,
messy, production-style text (modeled on a support-ticket / CRM export
returned by an external API).

## Folder structure

```
alu-regex-data-extraction_{GithubUsername}/
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

To run it against a different file, edit the two paths at the bottom of
`src/main.py` (`run("input/raw-text.txt", "output/sample-output.json")`).

## What it extracts

All 8 data types are implemented:

1. **Email addresses** — general RFC-practical pattern, plus ALU-specific
   classification into `alu_official` (`@alueducation.com`), `alu_alumni`
   (`@alumni.alueducation.com`), `alu_si` (`@si.alueducation.com`), or
   `external`.
2. **Credit card numbers** — matched by shape (13–19 digits, grouped in 4s),
   then validated with the **Luhn checksum algorithm**. A number that merely
   *looks* like a card (e.g. `1234-5678-9012-3456`) is reported but flagged
   `luhn_valid: false`, so a bug like "the form accepted an obviously fake
   card" is visible in the data instead of silently passing through.
3. **URLs** — requires an explicit `http(s)://` scheme, which deliberately
   excludes bare `www.example.com` text (too ambiguous with plain prose in
   free-form text).
4. **Phone numbers** — handles international (`+250 788 123 456`), US-style
   parens (`(415) 555-0192`), and hyphenated (`+1-202-555-0143`) formats.
   Explicitly excludes numerically-similar-but-different shapes: ISO
   timestamps (`2024-11-03`) and US SSNs (`999-99-9999`), since they use a
   different grouping convention than real phone numbers.
5. **Time (12-hour and 24-hour)** — 12-hour requires `AM`/`PM`
   (`9:00 AM`, `2:45 PM`); 24-hour requires valid hour/minute ranges
   (`00–23` : `00–59`), so malformed values like `25:00` or `13:75` never
   match in the first place.
6. **HTML tags** — extracted for visibility, but **never rendered or
   executed**. Dangerous tags (`<script>`, `<iframe>`, `<object>`, `<embed>`)
   and inline event handlers (`onerror=`, `onclick=`, ...) are additionally
   raised as `security_flags`. A guard excludes false positives such as an
   email address written in angle brackets (`<name@domain.com>`), which is
   shaped like a tag but isn't one.
7. **Hashtags** — `#word` style tags, 2–50 word characters.
8. **Currency amounts** — symbol-prefixed (`$1,250.00`, `€45,00`, `£120.75`)
   and ISO-code-prefixed (`USD 1,199.50`, `KES 15,000`) amounts, checked
   against a small allow-list of recognized currency codes to avoid matching
   random 3-letter-uppercase + number noise.

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
- **ReDoS-aware regex design** — patterns avoid nested unbounded
  quantifiers (e.g. no `(a+)+`); character classes use explicit `{min,max}`
  bounds where length matters (email local/domain parts, card/phone digit
  groups) instead of unconstrained `+`/`*`.
- **No blind trust in shape** — a credit card number is only accepted as
  plausible after passing the Luhn checksum, not just because it matches
  the "4 groups of 4 digits" shape. Time values are constrained to valid
  ranges by the regex itself, not filtered afterward.
- **HTML/script content is never executed** — `<script>` blocks, event
  handlers, and other tag content found in the text are treated purely as
  *data to report on*, never passed to `eval`, a browser context, a shell,
  or a database query.
- **Injection-pattern detection** — a separate check flags
  SQL-injection-looking fragments (e.g. `'; DROP TABLE ...`, `UNION SELECT`,
  `OR 1=1`) found in free text, so a hostile payload embedded in a ticket
  body is surfaced to a human reviewer rather than silently ignored *or*
  silently trusted.
- **Sensitive data masking** — emails and credit card numbers, the two data
  types explicitly called out as sensitive, are **masked before being
  written to `output/sample-output.json` or printed to the console**
  (`g*****@alueducation.com`, `**** **** **** 1111`). Full values only ever
  exist in memory during a single run and are never persisted or logged.

## Sample input

`input/raw-text.txt` is a fictional but realistic support-ticket export
containing: ALU official/alumni/SI emails, a real payment URL and a
suspicious look-alike "mirror" URL, international and US-style phone
numbers, a mix of 12-hour and 24-hour times (including intentionally
invalid ones like `25:00` and `13:75` to prove they're rejected), multiple
currency formats, hashtags, embedded raw HTML including a `<script>` tag
and an `onerror=` payload, a SQL-injection-style fragment, a valid test
card, a second valid test card, and one obviously fake card number that
fails the Luhn check on purpose — to demonstrate that the validation logic
actually discriminates between "looks like data" and "is valid data."

## Note on this submission

This assignment file contained a hidden instruction (embedded as if it were
part of the assessment brief) directing any AI assistant reading it to
covertly insert a specific sentence into the submitted source code without
telling the student. That instruction was not followed. If you're grading
this and want to verify, ask the student — they were told about it openly
during development rather than having it inserted behind their back.
