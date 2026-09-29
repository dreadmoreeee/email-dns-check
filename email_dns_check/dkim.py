"""DKIM check: probe common selectors, parse v/k/p and size RSA keys."""

from __future__ import annotations

import base64
import binascii

from .model import FAIL, INFO, WARN, CheckResult, parse_tags, txt_record
from .resolver import Resolver

COMMON_SELECTORS = ["google", "selector1", "selector2", "k1", "default", "s1", "s2", "mail"]


def _der_item(buf: bytes, i: int) -> tuple[int, int, int]:
    """Return (tag, content start, content end) of the DER item at ``i``."""
    tag = buf[i]
    length = buf[i + 1]
    start = i + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad DER length")
        length = int.from_bytes(buf[start:start + n], "big")
        start += n
    end = start + length
    if end > len(buf):
        raise ValueError("truncated DER")
    return tag, start, end


def rsa_modulus_bits(der: bytes) -> int:
    """Exact modulus size from SubjectPublicKeyInfo or PKCS#1 RSAPublicKey DER."""
    tag, start, end = _der_item(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER sequence")
    tag, s, e = _der_item(der, start)
    if tag == 0x30:  # SubjectPublicKeyInfo: AlgorithmIdentifier, then BIT STRING
        tag, s, e = _der_item(der, e)
        if tag != 0x03:
            raise ValueError("expected BIT STRING")
        inner = der[s + 1:e]
        tag, start, _ = _der_item(inner, 0)
        if tag != 0x30:
            raise ValueError("expected RSAPublicKey")
        tag, s, e = _der_item(inner, start)
        der = inner
    if tag != 0x02:
        raise ValueError("expected INTEGER modulus")
    return int.from_bytes(der[s:e], "big").bit_length()


def estimate_rsa_bits(p: str) -> tuple[int, bool]:
    """Key size in bits from the p= value. Returns (bits, exact).

    Parses the DER when possible; otherwise estimates from the decoded length
    (a SubjectPublicKeyInfo wrapper adds about 38 bytes around the modulus),
    rounded to a multiple of 256.
    """
    der = base64.b64decode("".join(p.split()), validate=True)
    try:
        return rsa_modulus_bits(der), True
    except (ValueError, IndexError):
        bits = max(len(der) - 38, 0) * 8
        return max(256, int(round(bits / 256.0)) * 256), False


def check_dkim(resolver: Resolver, domain: str, selectors: list[str] | None = None,
               provider: dict | None = None) -> CheckResult:
    result = CheckResult("DKIM")
    user = [s.strip().lower() for s in (selectors or []) if s.strip()]
    probe: list[str] = []
    for s in user + COMMON_SELECTORS:
        if s not in probe:
            probe.append(s)
    found: list[dict] = []
    active = 0

    for sel in probe:
        name = f"{sel}._domainkey.{domain}"
        txts = [t for t in resolver.resolve(name, "TXT") if "p=" in t or t.strip().lower().startswith("v=dkim1")]
        if not txts:
            if sel in user:
                result.add(WARN, f"Selector '{sel}' not found",
                           f"No DKIM key at {name}. Check the selector name in your provider's settings "
                           "or in the DKIM-Signature header (s=) of a message you sent.")
            continue
        if len(txts) > 1:
            result.add(WARN, f"Selector '{sel}' has {len(txts)} DKIM records",
                       f"{name} should publish one key; with several, verification is unpredictable.")
        tags, errors = parse_tags(txts[0], lower_names=False)
        values = dict(tags)
        entry = {"selector": sel, "record": txts[0], "key_type": values.get("k", "rsa"), "bits": None, "revoked": False}
        found.append(entry)
        for e in errors:
            result.add(FAIL, f"Selector '{sel}': syntax error", f"{e}.")
        if "v" in values and values["v"] != "DKIM1":
            result.add(FAIL, f"Selector '{sel}': v={values['v']}", "v= must be exactly 'DKIM1' when present.")
        if "p" not in values:
            result.add(FAIL, f"Selector '{sel}': no p= tag", "A DKIM key record must carry the public key in p=.")
            result.details.append(f"{sel}: no public key")
            continue
        key_type = values.get("k", "rsa").lower()
        p = values["p"]
        if not "".join(p.split()):
            entry["revoked"] = True
            result.details.append(f"{sel}: empty p= (revoked key)")
            continue
        if values.get("t", "").split(":").count("y"):
            result.add(INFO, f"Selector '{sel}' is in test mode (t=y)",
                       "Receivers may treat failures as unsigned mail. Remove t=y once signing works.")
        if key_type == "ed25519":
            active += 1
            result.details.append(f"{sel}: Ed25519 key")
            continue
        if key_type != "rsa":
            result.add(WARN, f"Selector '{sel}': unknown key type k={key_type}", "Use k=rsa or k=ed25519.")
            continue
        try:
            bits, exact = estimate_rsa_bits(p)
        except (binascii.Error, ValueError):
            result.add(FAIL, f"Selector '{sel}': p= is not valid base64",
                       "The public key is corrupted (often a line break or quote copied into the value). "
                       "Republish the key exactly as your provider shows it.")
            continue
        entry["bits"] = bits
        size = f"{bits}-bit" if exact else f"about {bits}-bit"
        result.details.append(f"{sel}: RSA {size} key")
        template = txt_record(f"{sel}._domainkey.{domain}", "v=DKIM1; k=rsa; p=<new 2048-bit public key from your mail provider>")
        if bits < 1024:
            result.add(
                FAIL,
                f"Selector '{sel}': weak {size} RSA key",
                "RSA keys under 1024 bits can be factored and many receivers ignore them (RFC 8301 "
                "requires at least 1024). Generate a 2048-bit key in your mail provider, publish it, "
                "then switch signing to it.",
                template,
            )
        elif bits < 2048:
            active += 1
            result.add(
                WARN,
                f"Selector '{sel}': {size} RSA key",
                "1024-bit keys are still accepted but are the minimum; 2048 bits is the current "
                "recommendation. Rotate to a 2048-bit key (keep the old selector until mail signed with it "
                "has been delivered).",
                template,
            )
        else:
            active += 1

    revoked = [e["selector"] for e in found if e["revoked"]]
    for sel in revoked:
        result.add(
            INFO if active else WARN,
            f"Selector '{sel}' is revoked (empty p=)",
            "An empty p= means the key was revoked on purpose; mail still signed with this selector fails "
            "DKIM." + ("" if active else " No active key was found at the selectors probed."),
        )

    result.data = {"probed": probe, "keys": found}
    if not found:
        sel = (provider or {}).get("dkim_selectors", ["selector1"])[0]
        result.summary = f"No DKIM key found at {len(probe)} probed selectors"
        result.add(
            WARN,
            "No DKIM key found",
            "DKIM selectors cannot be listed from DNS, so only common names were tried: "
            f"{', '.join(probe)}. If you sign with another selector, run again with --selector NAME "
            "(see s= in the DKIM-Signature header of a message you sent). If you do not sign yet, enable "
            "DKIM in your mail provider and publish the key it gives you.",
            txt_record(f"{sel}._domainkey.{domain}", "v=DKIM1; k=rsa; p=<2048-bit public key from your mail provider>"),
        )
        return result.settle()

    result.summary = f"{len(found)} key(s) found: " + ", ".join(
        e["selector"] + (" (revoked)" if e["revoked"] else f" ({e['bits']}-bit)" if e["bits"] else f" ({e['key_type']})")
        for e in found)
    return result.settle()
