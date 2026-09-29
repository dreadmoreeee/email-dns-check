# email-dns-check

Check a domain's email authentication DNS records (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI). It explains every problem it finds and prints **the exact record to publish**.

```
$ email-dns-check example.com
...
DMARC: WARN - p=none, aggregate reports on
  [WARN] DMARC policy is p=none (monitoring only)
         p=none tells receivers to take no action on mail that fails DMARC ...
         Publish: _dmarc.example.com. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

Why another checker:

- **Fixes, not just grades.** Each problem comes with an explanation and a zone-file line you can paste into your DNS provider, built from your current record (only the broken part changes).
- **SPF evaluated like a receiver.** The tool expands `include`/`redirect` recursively and counts the 10 DNS-lookup limit (include, a, mx, ptr, exists, redirect) and the limit of 2 void lookups. It also detects include loops, multiple records, syntax errors, `+all`, `?all`, a missing `all` and `ptr`.
- **DMARC explained.** It covers what `p=none` actually does, `sp`, `pct`, `rua`/`ruf` addresses (including the authorisation record that external report destinations need), `adkim`/`aspf` and `fo`. It suggests the staged path none -> quarantine -> reject.
- **DKIM key strength.** It probes common selectors (`google`, `selector1`, `selector2`, `k1`, `default`, `s1`, `s2`, `mail`) plus your own. Revoked keys (empty `p=`) are flagged. RSA key size is read from the key, and keys under 1024 bits are flagged, with 2048 recommended.
- **Polite.** DNS only, plus at most one HTTPS GET per domain (the MTA-STS policy), and only when the `_mta-sts` record exists. No redirects are followed, requests are at least 1 s apart and they carry a clear User-Agent.
- **One dependency** ([dnspython](https://www.dnspython.org/)), Python 3.10+.

## Install

```
pip install .
```

(or run from a checkout with `python -m email_dns_check` after `pip install dnspython`)

## Usage

```
email-dns-check DOMAIN [DOMAIN ...] [--selector S] [--format text|json|markdown] [--no-https]
python -m email_dns_check DOMAIN ...
```

- `--selector S` / `-s S`: extra DKIM selector to probe (repeatable). Find yours in the `s=` tag of the `DKIM-Signature` header of a message you sent.
- `--format`: `text` (default), `json` (for scripts; see [examples/sample-report.json](examples/sample-report.json)) or `markdown`.
- `--no-https`: DNS only; do not fetch the MTA-STS policy file.
- `--timeout SECONDS`: DNS timeout per query (default 5).

Each check is `pass`, `warn`, `fail` or `info` (optional feature not set up). **Exit status:** `0` when no check failed (warnings allowed), `1` when at least one check failed, `2` on usage errors such as an invalid domain name. That makes it usable in CI:

```
email-dns-check example.com --format json > report.json || echo "fix your DNS"
```

From Python, DNS sits behind a one-method resolver, so you can check made-up records offline:

```python
from email_dns_check import FakeResolver, check_domain

records = {"example.com": {"MX": ["10 mx.example.com"], "TXT": ["v=spf1 mx +all"]},
           "mx.example.com": {"A": ["192.0.2.10"]}}
report = check_domain("example.com", FakeResolver(records), https=False)
report.check("SPF").status        # 'fail' ('+all')
```

[examples/recommended-records.zone](examples/recommended-records.zone) has a complete set of records for a Google Workspace domain.

## Measured result

A single run against demarkstudio.ca (Google Workspace) on 2026-09-29. It exited with status 0: warnings, no failures. No `_mta-sts` record exists, so no HTTPS request was made. Output unedited:

````markdown
# Email DNS check: demarkstudio.ca

Overall: **WARN**

| Check | Status | Summary |
|---|---|---|
| MX | PASS | 1 MX host(s) (Google Workspace), all resolve |
| SPF | PASS | 1 record, 1/10 DNS lookups, 0/2 void lookups, ends with ~all |
| DMARC | WARN | p=none, aggregate reports on |
| DKIM | PASS | 1 key(s) found: google (2048-bit) |
| MTA-STS | INFO | Not published (optional) |
| TLS-RPT | INFO | Not published (optional) |
| BIMI | INFO | Not published (optional) |

## MX: PASS

- 1 smtp.google.com -> 64.233.178.27, 74.125.197.26, 74.125.197.27, 64.233.178.26, 2607:f8b0:4020:c0b::1a, 2607:f8b0:4020:c0b::1b, 2607:f8b0:4020:c07::1a, 2607:f8b0:4020:c07::1b

## SPF: PASS

- record: v=spf1 include:_spf.google.com ~all

Expansion:

```text
include:_spf.google.com [lookup 1]
```

- **INFO: SPF ends with ~all (softfail).** '~all' vs '-all' is a policy choice. With DMARC enforcing, '~all' is common and safe; '-all' asks receivers to reject unlisted senders outright, which can also break forwarded mail.

## DMARC: WARN

- record: v=DMARC1; p=none; rua=mailto:hola@demarkstudio.ca
- policy: p=none, subdomains sp=(inherits p)
- rua: mailto:hola@demarkstudio.ca
- DKIM alignment adkim=r (relaxed: subdomains of the same organisational domain align)
- SPF alignment aspf=r (relaxed: subdomains of the same organisational domain align)

- **WARN: DMARC policy is p=none (monitoring only).** p=none tells receivers to take no action on mail that fails DMARC: spoofed mail is still delivered normally. It is the right first stage while you read the aggregate reports, but it does not protect the domain. Staged path: (1) p=none with rua reports while you check that every legitimate sender passes SPF or DKIM with alignment; (2) p=quarantine (optionally with pct below 100 at first) so failing mail goes to spam; (3) p=reject once reports stay clean.

  Publish: `_dmarc.demarkstudio.ca. TXT "v=DMARC1; p=quarantine; rua=mailto:hola@demarkstudio.ca"`

## DKIM: PASS

- google: RSA 2048-bit key

## MTA-STS: INFO

- **INFO: No MTA-STS record.** MTA-STS makes senders require TLS with a valid certificate when delivering to your MX hosts, blocking downgrade attacks. To enable it, serve a policy file as text/plain at https://mta-sts.demarkstudio.ca/.well-known/mta-sts.txt (valid HTTPS certificate for mta-sts.demarkstudio.ca) with mode: testing first, then publish the TXT record. Policy file: (one line each) version: STSv1 | mode: testing | mx: smtp.google.com | max_age: 604800

  Publish: `_mta-sts.demarkstudio.ca. TXT "v=STSv1; id=2026092901"`

## TLS-RPT: INFO

- **INFO: No TLS-RPT record.** TLS-RPT asks senders to email you daily reports of TLS problems delivering to your domain; useful alongside MTA-STS.

  Publish: `_smtp._tls.demarkstudio.ca. TXT "v=TLSRPTv1; rua=mailto:tlsrpt@demarkstudio.ca"`

## BIMI: INFO

- BIMI shows your logo in some inboxes; it needs DMARC p=quarantine or p=reject and, for Gmail, a verified mark certificate.
````

```
$ python -m pytest -q -p no:cacheprovider --import-mode=importlib email-dns-check
74 passed in 3.13s
```

The tests use a fake resolver and a local HTTP server on a random port: no internet and no real DNS.

## Limitations

- **DKIM selectors cannot be enumerated.** DNS has no way to list them, so only common names and the ones you pass with `--selector` are probed. "No DKIM key found" can mean you sign with another selector.
- The RSA key size is read from the key's DER encoding, falling back to an estimate from the length of `p=`. The tool does not verify signatures on real mail.
- SPF macros (`%{i}` and the like) are validated but not expanded. `exists` and macro terms count as lookups but are not resolved.
- DMARC is read at `_dmarc.<domain>` only. For a subdomain without its own record, receivers fall back to the organisational domain's record, which this tool does not look up (no public suffix list). External report destinations are not queried; the authorisation record they need is printed instead.
- MTA-STS: the policy is checked against your MX hosts, but the certificates on the MX hosts themselves are not tested (that needs an SMTP connection).
- BIMI: only the DNS record and the DMARC requirement are checked; the SVG logo and certificate are not downloaded.
- Results reflect what your resolver sees now. DNS caches (TTL) can hide a change you just made.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
