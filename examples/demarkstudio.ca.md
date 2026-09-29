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
