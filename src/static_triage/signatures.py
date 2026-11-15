from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

# Reads the Authenticode certificate embedded in a Windows program and says
# who it claims to be signed by.
#
# What this does NOT do, and must not be read as doing: it does not verify
# the certificate chain against a trusted root, and it does not check the
# file against the digest inside the signature. A publisher name here is
# therefore *claimed*, not proven -- anyone can self-sign a file with
# "Valve Corp" in the subject. What it is good for is the two questions that
# need no trust store: is this file signed at all, and is it signed by the
# same certificate as the files around it.

CERTIFICATE_DIRECTORY_INDEX = 4
PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B
MAX_CERTIFICATE_BYTES = 4 * 1024 * 1024
# Only the headers and the certificate table are read, never the whole
# program: a scan meets libraries tens of megabytes wide. Real PE headers sit
# inside a few kilobytes, so this is generous.
HEADER_BYTES = 64 * 1024
WIN_CERTIFICATE_HEADER = 8
# PKCS#7 SignedData, the only certificate type Authenticode uses.
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
CODE_SIGNING_EKU = x509.oid.ExtendedKeyUsageOID.CODE_SIGNING
TIME_STAMPING_EKU = x509.oid.ExtendedKeyUsageOID.TIME_STAMPING


class SignatureError(ValueError):
    """A file whose signature could not be read."""


@dataclass(frozen=True, slots=True)
class PESignature:
    """What one program's embedded certificate claims."""

    relative_path: str
    signed: bool
    publisher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    # SHA-256 of the signing certificate itself, for grouping files by signer.
    fingerprint: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    certificate_count: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "signed": self.signed,
            "publisher": self.publisher,
            "subject": self.subject,
            "issuer": self.issuer,
            "fingerprint": self.fingerprint,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "certificate_count": self.certificate_count,
            "error": self.error,
            "verified": False,
            "verification_note": (
                "The certificate chain and the signed file digest are not "
                "checked, so the publisher is claimed, not proven."
            ),
        }


def _read_exactly(data: bytes, offset: int, length: int, what: str) -> bytes:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise SignatureError(f"{what} runs past the end of the file")
    return data[offset : offset + length]


def _certificate_table(data: bytes) -> tuple[int, int]:
    """The file offset and size of the certificate table, or (0, 0)."""

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SignatureError("not a PE file (no MZ header)")
    (pe_offset,) = struct.unpack_from("<I", _read_exactly(data, 0x3C, 4, "e_lfanew"))
    if _read_exactly(data, pe_offset, 4, "PE signature") != b"PE\0\0":
        raise SignatureError("not a PE file (no PE signature)")

    optional_header = pe_offset + 24
    (magic,) = struct.unpack_from(
        "<H", _read_exactly(data, optional_header, 2, "optional header")
    )
    if magic == PE32_MAGIC:
        directories = optional_header + 96
    elif magic == PE32PLUS_MAGIC:
        directories = optional_header + 112
    else:
        raise SignatureError(f"unknown PE optional header magic 0x{magic:x}")

    (number_of_directories,) = struct.unpack_from(
        "<I", _read_exactly(data, optional_header + (92 if magic == PE32_MAGIC else 108), 4,
                            "data directory count")
    )
    if number_of_directories <= CERTIFICATE_DIRECTORY_INDEX:
        return 0, 0
    entry = directories + CERTIFICATE_DIRECTORY_INDEX * 8
    # For this one directory the first field is a file offset, not an RVA.
    offset, size = struct.unpack_from(
        "<II", _read_exactly(data, entry, 8, "certificate table entry")
    )
    return offset, size


def _signed_data(table: bytes, size: int) -> bytes:
    """The PKCS#7 blob inside the certificate table."""

    if len(table) < WIN_CERTIFICATE_HEADER:
        raise SignatureError("the certificate table is cut off")
    length, _revision, certificate_type = struct.unpack_from("<IHH", table)
    if certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        raise SignatureError(f"unsupported certificate type {certificate_type}")
    if length < WIN_CERTIFICATE_HEADER or length > min(size, len(table)):
        raise SignatureError("the certificate entry's length is out of range")
    return _trim_to_der(table[WIN_CERTIFICATE_HEADER:length])


def _trim_to_der(blob: bytes) -> bytes:
    """Drop the padding after the PKCS#7 structure.

    The certificate table is padded to a multiple of 8 bytes, and the padding
    would otherwise reach the ASN.1 parser as trailing data.
    """

    if len(blob) < 2 or blob[0] != 0x30:
        raise SignatureError("the signature is not an ASN.1 sequence")
    first = blob[1]
    if first < 0x80:
        end = 2 + first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or len(blob) < 2 + count:
            raise SignatureError("the signature's length field is malformed")
        end = 2 + count + int.from_bytes(blob[2 : 2 + count], "big")
    if end > len(blob):
        raise SignatureError("the signature is shorter than its length field")
    return blob[:end]


def _signing_certificate(
    certificates: list[x509.Certificate],
) -> x509.Certificate | None:
    """Pick the code-signing leaf out of the certificates in the blob.

    The blob holds the signer's certificate, the intermediates above it, and
    often a timestamping authority's chain as well. The leaf is one that
    issued nothing else in the blob; extended key usage separates the signer
    from the timestamp.
    """

    if not certificates:
        return None
    issuers = {certificate.subject for certificate in certificates}
    leaves = [
        certificate
        for certificate in certificates
        if not any(
            other is not certificate and other.issuer == certificate.subject
            for other in certificates
        )
    ] or list(certificates)

    def usage(certificate: x509.Certificate) -> set[Any]:
        try:
            extension = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            )
        except x509.ExtensionNotFound:
            return set()
        return set(extension.value)

    signing = [leaf for leaf in leaves if CODE_SIGNING_EKU in usage(leaf)]
    if signing:
        return signing[0]
    # No explicit code-signing usage: drop anything that is only a timestamp.
    plain = [leaf for leaf in leaves if TIME_STAMPING_EKU not in usage(leaf)]
    candidates = plain or leaves
    # Prefer one whose issuer is also present: that is a real chain.
    chained = [leaf for leaf in candidates if leaf.issuer in issuers - {leaf.subject}]
    return (chained or candidates)[0]


def _name(subject: x509.Name) -> str:
    parts = [f"{attribute.oid._name}={attribute.value}" for attribute in subject]
    return ", ".join(parts)


def _common_name(subject: x509.Name) -> str | None:
    for oid in (x509.oid.NameOID.COMMON_NAME, x509.oid.NameOID.ORGANIZATION_NAME):
        found = subject.get_attributes_for_oid(oid)
        if found and isinstance(found[0].value, str):
            return found[0].value
    return None


def read_signature(path: Path, relative_path: str | None = None) -> PESignature:
    """Read one program's embedded certificate. Never raises for a bad file."""

    name = relative_path if relative_path is not None else path.name
    try:
        with path.open("rb") as handle:
            head = handle.read(HEADER_BYTES)
            try:
                offset, size = _certificate_table(head)
            except SignatureError as exc:
                return PESignature(name, False, error=str(exc))
            except (struct.error, ValueError) as exc:
                return PESignature(name, False, error=f"malformed PE header: {exc}")
            if offset == 0 or size == 0:
                return PESignature(name, False, error="the file is not signed")
            if size > MAX_CERTIFICATE_BYTES:
                return PESignature(
                    name, True, error="the certificate table is implausibly large"
                )
            handle.seek(offset)
            table = handle.read(size)
    except OSError as exc:
        return PESignature(name, False, error=f"could not be read: {exc.strerror or exc}")

    try:
        blob = _signed_data(table, size)
    except SignatureError as exc:
        return PESignature(name, True, error=str(exc))
    except (struct.error, ValueError) as exc:
        return PESignature(name, True, error=f"malformed signature: {exc}")

    try:
        certificates = list(pkcs7.load_der_pkcs7_certificates(blob))
    except Exception as exc:  # the library raises several unrelated types
        return PESignature(
            name, True, error=f"the signature could not be parsed: {type(exc).__name__}"
        )

    certificate = _signing_certificate(certificates)
    if certificate is None:
        return PESignature(
            name, True, certificate_count=0,
            error="the signature holds no certificates",
        )
    return PESignature(
        relative_path=name,
        signed=True,
        publisher=_common_name(certificate.subject),
        subject=_name(certificate.subject),
        issuer=_common_name(certificate.issuer),
        fingerprint=hashlib.sha256(
            certificate.public_bytes(Encoding.DER)
        ).hexdigest(),
        not_before=certificate.not_valid_before_utc.isoformat(),
        not_after=certificate.not_valid_after_utc.isoformat(),
        certificate_count=len(certificates),
    )


def summarize(signatures: Iterable[PESignature]) -> dict[str, Any]:
    """Group files by signer so the odd one out is visible without a trust store."""

    found = list(signatures)
    signers: dict[str, dict[str, Any]] = {}
    unsigned: list[str] = []
    unreadable: list[str] = []
    for signature in found:
        if signature.fingerprint:
            signer = signers.setdefault(
                signature.fingerprint,
                {
                    "publisher": signature.publisher,
                    "subject": signature.subject,
                    "issuer": signature.issuer,
                    "not_after": signature.not_after,
                    "paths": [],
                },
            )
            signer["paths"].append(signature.relative_path)
        elif signature.signed:
            unreadable.append(signature.relative_path)
        else:
            unsigned.append(signature.relative_path)

    ranked = sorted(signers.values(), key=lambda s: (-len(s["paths"]), s["publisher"] or ""))
    return {
        "files": len(found),
        "signed": sum(1 for s in found if s.fingerprint),
        "unsigned": unsigned,
        "unreadable": unreadable,
        "signers": ranked,
        "verified": False,
    }


# --- walking a folder ---------------------------------------------------------

MAX_WALKED_FILES = 50_000
MAX_LISTED_PATHS = 25


def find_programs(root: Path) -> list[Path]:
    """Every Windows program under root, found by its MZ header, not its name."""

    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(found) >= MAX_WALKED_FILES:
            break
        if path.is_symlink() or not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                if handle.read(2) == b"MZ":
                    found.append(path)
        except OSError:
            continue
    return found


def render(root: Path, signatures: list[PESignature]) -> list[str]:
    summary = summarize(signatures)
    lines = [
        "",
        f"Signing certificates in {root}",
        f"{summary['files']} programs found, {summary['signed']} signed.",
    ]
    for signer in summary["signers"]:
        paths = signer["paths"]
        lines.extend([
            "",
            f"  {signer['publisher'] or 'unnamed certificate'} "
            f"\u2014 {len(paths)} program{'' if len(paths) == 1 else 's'}",
            f"      issued by {signer['issuer'] or 'unknown'}, "
            f"expires {(signer['not_after'] or '?')[:10]}",
        ])
        for path in paths[:MAX_LISTED_PATHS]:
            lines.append(f"      {path}")
        if len(paths) > MAX_LISTED_PATHS:
            lines.append(f"      ... and {len(paths) - MAX_LISTED_PATHS} more")
    for label, key in (("Not signed", "unsigned"), ("Signature unreadable", "unreadable")):
        paths = summary[key]
        if paths:
            lines.extend(["", f"  {label} ({len(paths)}):"])
            lines.extend(f"      {path}" for path in paths[:MAX_LISTED_PATHS])
            if len(paths) > MAX_LISTED_PATHS:
                lines.append(f"      ... and {len(paths) - MAX_LISTED_PATHS} more")
    lines.extend([
        "",
        "The certificate chain and the signed file digest are NOT checked, so a",
        "publisher name here is claimed, not proven. What it does show is which",
        "files share a signer, and which carry no signature at all.",
    ])
    return lines


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="signatures.sh",
        description=(
            "Report the Authenticode certificate each Windows program in a "
            "folder claims to be signed by."
        ),
    )
    parser.add_argument("folder", help="the folder to inspect")
    args = parser.parse_args(argv)

    root = Path(args.folder).expanduser()
    if not root.is_dir():
        raise SystemExit(f"No folder at {root}")
    programs = find_programs(root)
    if not programs:
        raise SystemExit(f"No Windows programs found under {root}")
    signatures = [
        read_signature(path, path.relative_to(root).as_posix()) for path in programs
    ]
    for line in render(root, signatures):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
