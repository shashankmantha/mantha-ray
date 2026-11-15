from __future__ import annotations

import base64
import datetime
import struct
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from static_triage.models import EntryKind, EntryState, InventoryEntry, RoutingClass
from static_triage import signatures
from static_triage.signatures import (
    MISMATCH_EVIDENCE,
    PESignature,
    check_entries,
    _signing_certificate,
    find_programs,
    read_signature,
    render,
    summarize,
)

FIXTURES = Path(__file__).parent / "fixtures"
# Built with i686-w64-mingw32-gcc and signed with osslsigncode against a
# throwaway three-certificate chain: leaf "Klei Entertainment Test" <-
# "Mantha Test Intermediate" <- "Mantha Test Root CA".
SIGNED = "signed.dll.b64"
UNSIGNED = "unsigned.dll.b64"
_KEY_CACHE: list[rsa.RSAPrivateKey] = []


def fixture(name: str, directory: Path) -> Path:
    path = directory / name.removesuffix(".b64")
    path.write_bytes(base64.b64decode((FIXTURES / name).read_text()))
    return path


def key() -> rsa.RSAPrivateKey:
    # Generating RSA keys is slow; these certificates are never verified.
    if not _KEY_CACHE:
        _KEY_CACHE.append(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    return _KEY_CACHE[0]


def certificate(
    common_name: str,
    issuer: str | None = None,
    *,
    usage: object | None = None,
    ca: bool = False,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuer or common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if usage is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([usage]), critical=False
        )
    return builder.sign(key(), hashes.SHA256())


class LeafPickingTests(unittest.TestCase):
    """The blob holds the signer's chain and often a timestamp authority's too."""

    def test_signer_is_chosen_over_intermediates_and_the_timestamp(self) -> None:
        root = certificate("Vendor Root CA", ca=True)
        intermediate = certificate("Vendor Signing CA", "Vendor Root CA", ca=True)
        signer = certificate(
            "Klei Entertainment", "Vendor Signing CA", usage=ExtendedKeyUsageOID.CODE_SIGNING
        )
        timestamp_root = certificate("Timestamp Root CA", ca=True)
        timestamp = certificate(
            "Some Timestamping Authority",
            "Timestamp Root CA",
            usage=ExtendedKeyUsageOID.TIME_STAMPING,
        )
        bag = [root, timestamp, intermediate, timestamp_root, signer]
        chosen = _signing_certificate(bag)
        self.assertIsNotNone(chosen)
        self.assertEqual(
            chosen.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Klei Entertainment",
        )

    def test_a_signer_without_declared_usage_still_beats_a_timestamp(self) -> None:
        signer = certificate("Quiet Vendor", "Vendor Signing CA")
        timestamp = certificate(
            "Timestamping Authority", usage=ExtendedKeyUsageOID.TIME_STAMPING
        )
        chosen = _signing_certificate([timestamp, signer])
        self.assertEqual(
            chosen.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Quiet Vendor",
        )

    def test_no_certificates(self) -> None:
        self.assertIsNone(_signing_certificate([]))


class ReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_a_signed_program(self) -> None:
        result = read_signature(fixture(SIGNED, self.root), "bin/game.dll")
        self.assertEqual(
            (result.relative_path, result.signed, result.publisher, result.error),
            ("bin/game.dll", True, "Klei Entertainment Test", None),
        )
        self.assertEqual(result.issuer, "Mantha Test Intermediate")
        self.assertEqual(result.certificate_count, 3)
        self.assertRegex(result.fingerprint or "", r"^[0-9a-f]{64}$")
        self.assertIn("Klei Test", result.subject or "")
        # The signature was made over the bytes that are in the file.
        self.assertIs(result.covers_file, True)
        self.assertFalse(result.tampered)
        # The publisher claim is never presented as proven.
        payload = result.to_dict()
        self.assertFalse(payload["chain_verified"])
        self.assertFalse(payload["tampered"])
        self.assertIn("claimed, not proven", payload["verification_note"])
        self.assertIn("checked against the file's own bytes", payload["verification_note"])

    def test_a_modified_file_keeps_its_certificate_but_loses_its_digest(self) -> None:
        """The attack this guards against: a vendor signature on a changed file."""

        path = fixture(SIGNED, self.root)
        data = bytearray(path.read_bytes())
        # Flip one byte well inside the code, leaving every header and the
        # certificate table untouched, as copying a signature across would.
        data[0x600] ^= 0xFF
        path.write_bytes(bytes(data))

        result = read_signature(path, "bin/steam_api64.dll")
        # The certificate still reads as the vendor's...
        self.assertEqual(result.publisher, "Klei Entertainment Test")
        self.assertTrue(result.signed)
        # ...but it does not cover this file.
        self.assertIs(result.covers_file, False)
        self.assertTrue(result.tampered)
        self.assertTrue(result.to_dict()["tampered"])

    def test_a_file_whose_layout_cannot_be_hashed(self) -> None:
        """An unhashable layout is reported as unknown, never as a match."""

        path = fixture(SIGNED, self.root)
        data = bytearray(path.read_bytes())
        (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
        # Claim far more sections than a real PE has.
        struct.pack_into("<H", data, pe_offset + 6, 4000)
        path.write_bytes(bytes(data))
        result = read_signature(path, "x.dll")
        self.assertIsNone(result.covers_file)
        self.assertFalse(result.tampered)

    def test_an_unsigned_program(self) -> None:
        result = read_signature(fixture(UNSIGNED, self.root), "bin/crack.dll")
        self.assertEqual((result.signed, result.publisher), (False, None))
        self.assertEqual(result.error, "the file is not signed")

    def test_damaged_and_unrelated_files_never_raise(self) -> None:
        signed = (FIXTURES / SIGNED).read_text()
        data = base64.b64decode(signed)
        cases = {
            "not a PE": b"#!/bin/sh\necho hello\n",
            "empty": b"",
            "MZ only": b"MZ" + b"\0" * 200,
            "truncated after the header": data[:512],
            "certificate table cut off": data[: len(data) - 2000],
        }
        for label, content in cases.items():
            with self.subTest(case=label):
                path = self.root / "sample.bin"
                path.write_bytes(content)
                result = read_signature(path, label)
                self.assertIsNotNone(result.error, label)
                self.assertIsNone(result.publisher)

    def test_a_garbled_signature_is_reported_not_trusted(self) -> None:
        path = fixture(SIGNED, self.root)
        data = bytearray(path.read_bytes())
        # Corrupt the middle of the certificate table.
        data[len(data) - 400 : len(data) - 360] = b"\xff" * 40
        path.write_bytes(bytes(data))
        result = read_signature(path, "bin/game.dll")
        self.assertTrue(result.signed)
        self.assertIsNone(result.publisher)
        self.assertIsNotNone(result.error)

    def test_an_unreadable_file(self) -> None:
        result = read_signature(self.root / "missing.dll", "missing.dll")
        self.assertFalse(result.signed)
        self.assertIn("could not be read", result.error or "")

    def test_pe32_plus_is_understood(self) -> None:
        """The 64-bit optional header puts the data directories 16 bytes later."""

        path = fixture(SIGNED, self.root)
        data = bytearray(path.read_bytes())
        (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
        self.assertEqual(struct.unpack_from("<H", data, pe_offset + 24)[0], 0x10B)
        # A PE32+ file would be read from the later offset; check the parser
        # rejects an unknown magic rather than reading the wrong place.
        struct.pack_into("<H", data, pe_offset + 24, 0x1234)
        path.write_bytes(bytes(data))
        self.assertIn("magic", read_signature(path, "x.dll").error or "")


class SummaryTests(unittest.TestCase):
    def test_files_group_by_signer_and_the_odd_one_shows(self) -> None:
        klei = "a" * 64
        valve = "b" * 64
        found = [
            PESignature("bin/game.exe", True, "Klei Entertainment", fingerprint=klei,
                        covers_file=True),
            PESignature("bin/tier0_s.dll", True, "Klei Entertainment", fingerprint=klei,
                        covers_file=True),
            PESignature("bin/steam_api.dll", True, "Valve Corp", fingerprint=valve,
                        covers_file=False),
            PESignature("bin/steamclient.dll", False, error="the file is not signed"),
            PESignature("bin/odd.dll", True, error="the signature could not be parsed"),
        ]
        summary = summarize(found)
        # odd.dll carries a signature that could not be parsed: it is signed,
        # but its signer cannot be named, so it counts in one and not the other.
        self.assertEqual((summary["files"], summary["signed"]), (5, 4))
        self.assertEqual(summary["identified"], 3)
        self.assertEqual(summary["covered"], 2)
        self.assertEqual(summary["unsigned"], ["bin/steamclient.dll"])
        self.assertEqual(summary["unreadable"], ["bin/odd.dll"])
        self.assertFalse(summary["chain_verified"])
        # The file wearing a signature that does not match is called out.
        self.assertEqual(
            summary["tampered"],
            [{"relative_path": "bin/steam_api.dll", "publisher": "Valve Corp"}],
        )
        valve_group = [s for s in summary["signers"] if s["publisher"] == "Valve Corp"][0]
        self.assertFalse(valve_group["covers_file"])
        # Biggest signer first, so the single-file signer stands out.
        self.assertEqual(
            [(s["publisher"], len(s["paths"])) for s in summary["signers"]],
            [("Klei Entertainment", 2), ("Valve Corp", 1)],
        )

    def test_nothing_to_summarize(self) -> None:
        summary = summarize([])
        self.assertEqual((summary["files"], summary["signed"], summary["signers"]), (0, 0, []))


class WalkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_programs_are_found_by_header_not_by_name(self) -> None:
        (self.root / "bin").mkdir()
        (self.root / "data").mkdir()
        # A library under a game's own extension is still a program.
        for name in ("bin/game.exe", "bin/tool.dle", "bin/plain.dll"):
            (self.root / name).write_bytes(
                base64.b64decode((FIXTURES / UNSIGNED).read_text())
            )
        (self.root / "data/level.pak").write_bytes(b"PACK" + b"\0" * 500)
        (self.root / "data/main.lua").write_text("return {}\n")
        (self.root / "data/empty").write_bytes(b"")
        found = sorted(p.relative_to(self.root).as_posix() for p in find_programs(self.root))
        self.assertEqual(found, ["bin/game.exe", "bin/plain.dll", "bin/tool.dle"])

    def test_symlinks_are_not_followed(self) -> None:
        real = self.root / "real.dll"
        real.write_bytes(base64.b64decode((FIXTURES / UNSIGNED).read_text()))
        try:
            (self.root / "link.dll").symlink_to(real)
        except OSError:
            self.skipTest("symlinks are not available here")
        found = [p.name for p in find_programs(self.root)]
        self.assertEqual(found, ["real.dll"])

    def test_report_names_the_odd_file_out(self) -> None:
        klei = "a" * 64
        text = "\n".join(render(Path("/games/ds"), [
            PESignature("bin/game.exe", True, "Klei Entertainment", fingerprint=klei,
                        issuer="Vendor CA", not_after="2027-01-02T00:00:00+00:00",
                        covers_file=True),
            PESignature("bin/tier0_s.dll", True, "Klei Entertainment", fingerprint=klei,
                        issuer="Vendor CA", not_after="2027-01-02T00:00:00+00:00",
                        covers_file=True),
            PESignature("bin/steamclient.dll", False, error="the file is not signed"),
        ]))
        self.assertIn("3 programs found, 2 signed, 2 whose signature matches", text)
        self.assertIn("Klei Entertainment \u2014 2 programs", text)
        self.assertIn("issued by Vendor CA, expires 2027-01-02", text)
        self.assertIn("Not signed (1):", text)
        self.assertIn("bin/steamclient.dll", text)
        self.assertIn("claimed rather", text)
        self.assertNotIn("DOES NOT MATCH", text)

    def test_report_shouts_about_a_mismatched_signature(self) -> None:
        text = "\n".join(render(Path("/games/dk2"), [
            PESignature("steam_api64.dll", True, "Valve Corp", fingerprint="c" * 64,
                        covers_file=False),
        ]))
        self.assertIn("*** SIGNATURE DOES NOT MATCH THE FILE (1) ***", text)
        self.assertIn("steam_api64.dll (claims Valve Corp)", text)
        self.assertIn("not every file here matches this signature", text)


class ScanIntegrationTests(unittest.TestCase):
    """Signature reading runs with the inventory and feeds the review items."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        (self.root / "bin").mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def entry(self, path: str, routing=RoutingClass.PE_DLL, **changes) -> InventoryEntry:
        return InventoryEntry(
            relative_path=path,
            kind=changes.pop("kind", EntryKind.REGULAR_FILE),
            state=changes.pop("state", EntryState.INVENTORIED),
            routing_class=routing,
            **changes,
        )

    def place(self, name: str, source: str, tamper: bool = False) -> None:
        data = bytearray(base64.b64decode((FIXTURES / source).read_text()))
        if tamper:
            data[0x600] ^= 0xFF
        (self.root / name).write_bytes(bytes(data))

    def test_a_mismatch_becomes_a_review_item(self) -> None:
        self.place("bin/game.exe", SIGNED)
        self.place("bin/steam_api64.dll", SIGNED, tamper=True)
        self.place("bin/crack.dll", UNSIGNED)
        entries = [
            self.entry("bin/game.exe", RoutingClass.PE_EXECUTABLE),
            self.entry("bin/steam_api64.dll"),
            self.entry("bin/crack.dll"),
        ]
        block, added = check_entries(entries, self.root)

        self.assertEqual(added, 1)
        self.assertEqual((block["files"], block["signed"], block["covered"]), (3, 2, 1))
        self.assertEqual(
            block["tampered"],
            [{"relative_path": "bin/steam_api64.dll",
              "publisher": "Klei Entertainment Test"}],
        )
        self.assertEqual(block["unsigned"], ["bin/crack.dll"])
        self.assertEqual(len(block["results"]), 3)

        # Only the mismatched file is flagged, and it says why.
        flagged = [e for e in entries if e.evidence]
        self.assertEqual([e.relative_path for e in flagged], ["bin/steam_api64.dll"])
        self.assertIn("Klei Entertainment Test", flagged[0].evidence[0])
        self.assertIn("copied signature", flagged[0].evidence[0])
        self.assertTrue(MISMATCH_EVIDENCE.startswith("signature does not match"))

    def test_only_windows_programs_are_looked_at(self) -> None:
        self.place("bin/game.exe", SIGNED)
        (self.root / "bin" / "level.pak").write_bytes(b"PACK" + b"\0" * 100)
        (self.root / "bin" / "gone.dll").write_bytes(b"MZ")
        entries = [
            self.entry("bin/game.exe", RoutingClass.PE_EXECUTABLE),
            self.entry("bin/level.pak", RoutingClass.OTHER),
            self.entry("bin/script.lua", RoutingClass.TEXT),
            self.entry("bin/tool", RoutingClass.ELF),
            self.entry("bin/gone.dll", state=EntryState.ERROR),
            self.entry("bin", RoutingClass.OTHER, kind=EntryKind.DIRECTORY),
        ]
        block, added = check_entries(entries, self.root)
        self.assertEqual((block["files"], added), (1, 0))
        self.assertEqual(block["results"][0]["relative_path"], "bin/game.exe")

    def test_a_missing_file_is_recorded_not_raised(self) -> None:
        block, added = check_entries([self.entry("bin/vanished.dll")], self.root)
        self.assertEqual(added, 0)
        self.assertEqual(block["files"], 1)
        self.assertIn("could not be read", block["results"][0]["error"])


class WithoutAParserTests(unittest.TestCase):
    """The tamper check must not depend on the optional X.509 parser.

    The container had no cryptography installed, which broke the whole
    scanner on import. Reading the certificate is optional; recomputing the
    digest is plain hashing, so a copied signature is still caught.
    """

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        data = bytearray(base64.b64decode((FIXTURES / SIGNED).read_text()))
        (self.root / "genuine.dll").write_bytes(bytes(data))
        data[0x600] ^= 0xFF
        (self.root / "cloned.dll").write_bytes(bytes(data))
        (self.root / "plain.dll").write_bytes(
            base64.b64decode((FIXTURES / UNSIGNED).read_text())
        )
        patcher = mock.patch.object(signatures, "CERTIFICATE_PARSER", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def read(self, name: str) -> PESignature:
        return read_signature(self.root / name, name)

    def test_a_copied_signature_is_still_caught(self) -> None:
        cloned = self.read("cloned.dll")
        self.assertTrue(cloned.signed)
        self.assertIs(cloned.covers_file, False)
        self.assertTrue(cloned.tampered)

    def test_a_genuine_signature_is_still_confirmed(self) -> None:
        genuine = self.read("genuine.dll")
        self.assertTrue(genuine.signed)
        self.assertIs(genuine.covers_file, True)
        self.assertFalse(genuine.tampered)

    def test_the_publisher_is_unknown_and_says_why(self) -> None:
        genuine = self.read("genuine.dll")
        self.assertIsNone(genuine.publisher)
        self.assertIsNone(genuine.fingerprint)
        self.assertIn("no X.509 parser", genuine.error or "")

    def test_an_unsigned_file_still_reads_as_unsigned(self) -> None:
        plain = self.read("plain.dll")
        self.assertFalse(plain.signed)
        self.assertFalse(plain.tampered)

    def test_the_report_block_still_counts_correctly(self) -> None:
        block = summarize([self.read(n) for n in
                           ("genuine.dll", "cloned.dll", "plain.dll")])
        # Both signed files still count as signed; neither signer is named.
        self.assertEqual(
            (block["files"], block["signed"], block["covered"]), (3, 2, 1)
        )
        self.assertEqual(block["identified"], 0)
        self.assertEqual(sorted(block["unreadable"]), ["cloned.dll", "genuine.dll"])
        self.assertEqual(
            [t["relative_path"] for t in block["tampered"]], ["cloned.dll"]
        )


class SummaryLineTests(unittest.TestCase):
    def test_lines(self) -> None:
        from static_triage.case_summary import signature_lines

        self.assertEqual(signature_lines(None), [])
        self.assertEqual(signature_lines({"files": 0}), [])
        clean = signature_lines({"files": 18, "signed": 6, "covered": 6, "tampered": []})
        self.assertEqual(clean, ["Signed   6 of 18 programs · 6 match their signature"])
        bad = signature_lines({
            "files": 18, "signed": 6, "covered": 5,
            "tampered": [{"relative_path": "bin/steam_api64.dll", "publisher": "Valve Corp"}],
        })
        self.assertIn("1 DO NOT MATCH:", bad[0])
        self.assertIn("bin/steam_api64.dll  claims Valve Corp", bad[1])


if __name__ == "__main__":
    unittest.main()
