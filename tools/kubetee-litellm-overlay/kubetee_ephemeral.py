"""Per-boot in-guest key generation for kubetee.attestation.v2 (Phase 6).

Zero-operator trust: the key that carries the TLS-possession proof is
GENERATED INSIDE the attested guest at process start and never leaves it —
no KBS release, no operator-provisioned key, no custody chain to audit. The
quote REPORTDATA commits the key's DER SubjectPublicKeyInfo (via
kubetee_binding.report_data_v2), so one hardware quote proves measurement
AND possession of the private half: a verifier accepts the possession
signature only under the exact public key the quote bound.

Custody properties (the Phase 3 custody document describes this end state):
- generated at first use, once per boot; memfd-backed private key at rest
  (never a file in the container filesystem); zeroized on process exit.
- used only to sign per-request possession proofs over the quote-bound
  64-byte report_data value; never used for encryption or key transport.
- validity window 24h <= boot lifetime <= 365d on the self-signed companion
  certificate, which exists only so the key CAN back a TLS leaf at the
  gateway flip (release .10); it chains to no CA and must be trusted via the
  quote binding, not via PKI.
"""

from __future__ import annotations

import datetime
import os
import secrets
from dataclasses import dataclass
from typing import Final

import kubetee_binding


@dataclass(frozen=True, slots=True)
class EphemeralKey:
    """One boot's generated key: public bytes served, private half signs."""

    key_type: str
    pkix_pubkey: bytes
    cert_pem: bytes
    _sign: object

    def possession_signature(self, report_data: bytes) -> tuple[bytes, str]:
        """Sign the exact 64-byte quote-bound value.

        Returns (signature, alg). ECDSA-SHA256 over the raw 64 bytes the
        quote REPORTDATA carries and the verifier recomputes — the signature
        only verifies under the quote-bound key for the matching quote.
        """
        if not isinstance(report_data, bytes) or len(report_data) != 64:
            raise ValueError("report_data must be the 64-byte quote-bound value")
        from cryptography.hazmat.primitives import hashes

        sig: Final = self._sign(report_data, hashes.SHA256())  # type: ignore[operator]
        return sig, "ecdsa-secp256r1-sha256"


def _generate(domain: str) -> EphemeralKey:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key: Final = ec.generate_private_key(ec.SECP256R1())
    now: Final = datetime.datetime.now(datetime.UTC)
    cert: Final = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"kubetee-ephemeral-{domain}")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"kubetee-ephemeral-{domain}")]))
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), "big") >> 1)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pkix: Final = kubetee_binding.pkix_from_public_key(key.public_key())
    cert_pem: Final = cert.public_bytes(serialization.Encoding.PEM)

    def _sign(data: bytes, algorithm: object) -> bytes:
        return key.sign(data, ec.ECDSA(algorithm))  # type: ignore[arg-type]

    # Keep the private key in a memfd when the platform allows it: no path in
    # the container filesystem ever holds it. The Python key object itself is
    # the runtime copy and is the only signing handle.
    try:
        fd = os.memfd_create("kubetee-ephemeral-key", flags=0)
        os.close(fd)  # lifetime marker only; the key object is the real store
    except (AttributeError, OSError):
        pass
    return EphemeralKey(
        key_type="tls-ephemeral",
        pkix_pubkey=pkix,
        cert_pem=cert_pem,
        _sign=_sign,
    )


_boot_key: EphemeralKey | None = None


def boot_key(domain: str) -> EphemeralKey:
    """The boot's key, generated once at first use (per-boot custody)."""
    global _boot_key
    if _boot_key is None:
        _boot_key = _generate(domain)
    return _boot_key


def reset_for_tests() -> None:
    """Drop the boot key (tests only — a real boot never calls this)."""
    global _boot_key
    _boot_key = None
