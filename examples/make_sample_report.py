"""Build examples/sample-report.json offline from made-up records for example.com.

Shows how to run the checks against a FakeResolver (no network needed):

    python examples/make_sample_report.py > examples/sample-report.json
"""

import base64
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from email_dns_check import FakeResolver, check_domain  # noqa: E402
from email_dns_check.report import render_json  # noqa: E402

# A 1024-bit RSA public key shape (the modulus is made up).
KEY_1024 = base64.b64encode(
    bytes.fromhex("30819f300d06092a864886f70d010101050003818d0030818902818100")
    + bytes([0xC3] * 128) + bytes.fromhex("0203010001")
).decode()

RECORDS = {
    "example.com": {
        "MX": ["1 smtp.google.com"],
        "TXT": ["v=spf1 include:_spf.google.com include:servers.mcsv.net ?all"],
    },
    "smtp.google.com": {"A": ["142.250.0.27"]},
    "_spf.google.com": {"TXT": [
        "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"]},
    "_netblocks.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ~all"]},
    "_netblocks2.google.com": {"TXT": ["v=spf1 ip6:2001:4860:4000::/36 ~all"]},
    "_netblocks3.google.com": {"TXT": ["v=spf1 ip4:172.217.0.0/19 ~all"]},
    "servers.mcsv.net": {"TXT": ["v=spf1 ip4:205.201.128.0/20 ~all"]},
    "_dmarc.example.com": {"TXT": ["v=DMARC1; p=none"]},
    "google._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={KEY_1024}"]},
}

if __name__ == "__main__":
    report = check_domain("example.com", FakeResolver(RECORDS), https=False)
    sys.stdout.write(render_json([report]))
