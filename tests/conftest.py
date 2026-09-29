import base64
import copy
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def make_rsa_key(bits: int, pkcs1: bool = False) -> str:
    """Base64 public key with a modulus of exactly ``bits`` bits (not a real key)."""
    modulus = (1 << (bits - 1)) | 1
    n = _der(0x02, b"\x00" + modulus.to_bytes(bits // 8, "big"))
    rsa = _der(0x30, n + _der(0x02, (65537).to_bytes(3, "big")))
    if pkcs1:
        return base64.b64encode(rsa).decode()
    alg = bytes.fromhex("300d06092a864886f70d0101010500")
    return base64.b64encode(_der(0x30, alg + _der(0x03, b"\x00" + rsa))).decode()


GOOD = {
    "example.com": {
        "MX": ["1 smtp.google.com"],
        "TXT": ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"],
        "A": ["192.0.2.1"],
    },
    "smtp.google.com": {"A": ["142.250.0.27"], "AAAA": ["2607:f8b0::1b"]},
    "_spf.google.com": {"TXT": [
        "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"]},
    "_netblocks.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"]},
    "_netblocks2.google.com": {"TXT": ["v=spf1 ip6:2001:4860:4000::/36 ~all"]},
    "_netblocks3.google.com": {"TXT": ["v=spf1 ip4:172.217.0.0/19 ~all"]},
    "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]},
    "google._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=" + make_rsa_key(2048)]},
}


@pytest.fixture
def records():
    """A healthy Google Workspace domain (example.com); tests modify a copy."""
    return copy.deepcopy(GOOD)


@pytest.fixture
def rsa_key():
    return make_rsa_key
