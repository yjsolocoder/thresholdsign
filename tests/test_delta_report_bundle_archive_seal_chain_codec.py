"""Tests for the canonical DeltaReportBundleArchiveSealChain transport
encoding: encode_delta_report_bundle_archive_seal_chain /
decode_delta_report_bundle_archive_seal_chain."""

import unittest

from thresholdsign import (
    AggregateSignature,
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSealChain,
    decode_delta_report_bundle_archive_seal_chain,
    drasc_message,
    encode_delta_report_bundle_archive_seal,
    encode_delta_report_bundle_archive_seal_chain,
    verify_dc,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_archive_codec import build_archives
from test_delta_report_bundle_archive_seal_codec import make_seal

WIRE_TAG = b"ts/drasc/w1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def seal_framing(items) -> bytes:
    out = bytearray(u32(len(items)))
    for item in items:
        encoded = encode_delta_report_bundle_archive_seal(item)
        out += u32(len(encoded))
        out += encoded
    return bytes(out)


def signature_frame(signature: AggregateSignature) -> bytes:
    out = bytearray(varint(signature.R))
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(chain: DeltaReportBundleArchiveSealChain) -> bytes:
    """Independently build the chain wire format straight from the spec."""
    return (
        WIRE_TAG
        + seal_framing(chain.items)
        + signature_frame(chain.signature)
    )


def wire_with_signature(items, sig_bytes: bytes) -> bytes:
    return WIRE_TAG + seal_framing(items) + sig_bytes


def make_chain(items, key, *, signer_ids=(1, 3), seed=2100):
    """Seal a tuple of archive seals with one outer signature of ``key``."""
    message = drasc_message(items, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return DeltaReportBundleArchiveSealChain(items, signature)


def make_items(key, full, first, second):
    return (
        make_seal(DeltaReportBundleArchive((full,)), key, seed=2000),
        make_seal(
            DeltaReportBundleArchive((first, second)), key, seed=2001
        ),
        make_seal(
            DeltaReportBundleArchive((second, full, first)), key, seed=2002
        ),
    )


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items = make_items(
            self.key, self.full, self.first, self.second
        )

    def test_honest_chains_round_trip_at_every_length(self):
        for n in range(1, len(self.items) + 1):
            chain = make_chain(self.items[:n], self.key, seed=2200 + n)
            wire = encode_delta_report_bundle_archive_seal_chain(chain)
            decoded = decode_delta_report_bundle_archive_seal_chain(wire)
            self.assertEqual(decoded, chain, msg=f"n={n}")
            self.assertEqual(
                encode_delta_report_bundle_archive_seal_chain(decoded),
                wire,
                msg=f"n={n}",
            )
            self.assertTrue(
                verify_dc(decoded, self.key), msg=f"n={n}"
            )

    def test_encoding_matches_independent_builder(self):
        chain = make_chain(self.items, self.key, seed=2210)
        wire = encode_delta_report_bundle_archive_seal_chain(chain)
        self.assertEqual(wire, build_wire(chain))
        self.assertTrue(wire.startswith(WIRE_TAG))
        self.assertEqual(
            wire[len(WIRE_TAG):len(WIRE_TAG) + 4], u32(len(self.items))
        )

    def test_layout_is_tag_count_frames_then_signature_frame(self):
        chain = make_chain(self.items, self.key, seed=2220)
        wire = encode_delta_report_bundle_archive_seal_chain(chain)
        offset = 0
        self.assertEqual(wire[offset:len(WIRE_TAG)], WIRE_TAG)
        offset += len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 4], u32(len(self.items)))
        offset += 4
        for item in self.items:
            encoded = encode_delta_report_bundle_archive_seal(item)
            self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(wire[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(wire[offset:], signature_frame(chain.signature))

    def test_order_is_preserved(self):
        chain = make_chain(self.items, self.key, seed=2230)
        decoded = decode_delta_report_bundle_archive_seal_chain(
            encode_delta_report_bundle_archive_seal_chain(chain)
        )
        self.assertEqual(decoded.items, self.items)
        self.assertEqual(decoded.signature, chain.signature)

    def test_encoding_is_unique_and_stateless(self):
        chain = make_chain(self.items, self.key, seed=2240)
        self.assertEqual(
            encode_delta_report_bundle_archive_seal_chain(chain),
            encode_delta_report_bundle_archive_seal_chain(chain),
        )

    def test_distinct_chains_encode_distinctly(self):
        forward = make_chain(self.items, self.key, seed=2250)
        reverse = make_chain(tuple(reversed(self.items)), self.key, seed=2251)
        self.assertNotEqual(
            encode_delta_report_bundle_archive_seal_chain(forward),
            encode_delta_report_bundle_archive_seal_chain(reverse),
        )

    def test_zero_z_round_trips(self):
        # z == 0 is structurally legal and encodes as the single byte 00.
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:1],
            AggregateSignature(R=5, z=0, signer_ids=(1, 3)),
        )
        wire = encode_delta_report_bundle_archive_seal_chain(chain)
        decoded = decode_delta_report_bundle_archive_seal_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertEqual(
            encode_delta_report_bundle_archive_seal_chain(decoded), wire
        )

    def test_large_signer_id_round_trips(self):
        # Signer ids are unbounded positive integers at the codec layer;
        # the signature is not checked, so a structurally legal signature
        # with wide ids round-trips without signing.
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:1],
            AggregateSignature(
                R=2 ** 100,
                z=2 ** 200,
                signer_ids=(1, 2 ** 31 - 1, 2 ** 64),
            ),
        )
        decoded = decode_delta_report_bundle_archive_seal_chain(
            encode_delta_report_bundle_archive_seal_chain(chain)
        )
        self.assertEqual(decoded, chain)


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items = make_items(
            self.key, self.full, self.first, self.second
        )

    def test_foreign_outer_signature_decodes_but_fails_verification(self):
        # The outer signature over a different item set is structurally
        # legal: the encoder must not check it, the decoder must restore
        # it, and verify_dc must report False.
        foreign = sign_message(
            self.key,
            drasc_message(
                (self.items[2], self.items[0]), self.key.public_key
            ),
            seed=2300,
        )
        chain = DeltaReportBundleArchiveSealChain(self.items[:2], foreign)
        wire = encode_delta_report_bundle_archive_seal_chain(chain)
        decoded = decode_delta_report_bundle_archive_seal_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertFalse(verify_dc(decoded, self.key))

    def test_bad_nested_bundle_decodes_but_fails_verification(self):
        # A seal over an archive containing a bundle its report does not
        # diagnose is structurally legal and round-trips; its own
        # verification is False, which verify_dc reports.
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_bundle = DeltaReportBundle(
            self.full.segments,
            DeltaReport(
                diagnosis,
                self.full.report.public_key,
                self.full.report.signature,
            ),
        )
        bad_archive = DeltaReportBundleArchive((self.first, bad_bundle))
        bad_seal = make_seal(bad_archive, self.key, seed=2310)
        chain = make_chain(
            (self.items[0], bad_seal), self.key, seed=2311
        )
        decoded = decode_delta_report_bundle_archive_seal_chain(
            encode_delta_report_bundle_archive_seal_chain(chain)
        )
        self.assertEqual(decoded, chain)
        self.assertFalse(verify_dc(decoded, self.key))

    def test_other_key_decodes_but_fails_verification(self):
        chain = make_chain(self.items, self.key, seed=2320)
        decoded = decode_delta_report_bundle_archive_seal_chain(
            encode_delta_report_bundle_archive_seal_chain(chain)
        )
        self.assertFalse(verify_dc(decoded, make_other_key()))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items = make_items(
            self.key, self.full, self.first, self.second
        )
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        self.chain = make_chain(self.items, self.key, seed=2400)

    def test_non_chain_type_error(self):
        for bad in (
            "x",
            None,
            42,
            b"x",
            object(),
            self.items,
            self.items[0],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_tuple_items_type_error(self):
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(
                        bad, self.chain.signature
                    )
                )

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(
                        (bad,), self.chain.signature
                    )
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(
                        (self.items[0], bad), self.chain.signature
                    )
                )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal_chain(
                DeltaReportBundleArchiveSealChain((), self.signature)
            )

    def test_illegal_nested_seal_value_error(self):
        # An archive seal over an empty archive is structurally illegal;
        # it is legal to construct but the chain encoder rejects it.
        bad_seal = type(self.items[0])(
            DeltaReportBundleArchive(()), self.signature
        )
        bad = DeltaReportBundleArchiveSealChain((bad_seal,), self.signature)
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal_chain(bad)
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal_chain(
                DeltaReportBundleArchiveSealChain(
                    (self.items[0], bad_seal), self.signature
                )
            )

    def test_illegal_outer_signature_value_error(self):
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(0, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(self.items, bad)
                )

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5, 5.0, True, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(self.items, bad)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items = make_items(
            self.key, self.full, self.first, self.second
        )
        self.chain = make_chain(self.items, self.key, seed=2500)
        self.wire = encode_delta_report_bundle_archive_seal_chain(
            self.chain
        )

    def test_non_bytes_type_error(self):
        for bad in ("not bytes", bytearray(self.wire), None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_report_bundle_archive_seal_chain(bad)

    def test_bad_tag(self):
        rest = self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                b"ts/drasc/w2" + rest
            )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                b"x" + self.wire[1:]
            )

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_delta_report_bundle_archive_seal_chain(
                    self.wire[:cut]
                )

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                self.wire + b"\x00"
            )

    def test_zero_count_rejected(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG + u32(0)
            )

    def test_declared_count_too_large_then_truncated(self):
        body = self.wire[len(WIRE_TAG) + 4:]
        bad = WIRE_TAG + u32(len(self.items) + 1) + body
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_declared_count_too_small_leaves_trailing(self):
        bodies = []
        for item in self.items:
            encoded = encode_delta_report_bundle_archive_seal(item)
            bodies.append(u32(len(encoded)) + encoded)
        bad = (
            WIRE_TAG
            + u32(1)
            + b"".join(bodies)
            + signature_frame(self.chain.signature)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_zero_frame_length_rejected(self):
        first = encode_delta_report_bundle_archive_seal(self.items[0])
        rest = self.wire[
            len(WIRE_TAG) + 4 + 4 + len(first):
        ]
        bad = WIRE_TAG + u32(2) + u32(0) + first + rest
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_declared_frame_length_too_long(self):
        first = encode_delta_report_bundle_archive_seal(self.items[0])
        rest = self.wire[
            len(WIRE_TAG) + 4 + 4 + len(first):
        ]
        bad = (
            WIRE_TAG
            + u32(2)
            + u32(len(first) + 1)
            + first
            + rest
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_junk_nested_frame_rejected(self):
        bad = (
            WIRE_TAG
            + u32(1)
            + u32(4)
            + b"junk"
            + signature_frame(self.chain.signature)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_nested_non_canonical_encoding_rejected(self):
        first = encode_delta_report_bundle_archive_seal(self.items[0])
        tampered = b"x" + first[1:]
        bad = (
            WIRE_TAG
            + u32(1)
            + u32(len(tampered))
            + tampered
            + signature_frame(self.chain.signature)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    # -- outer signature frame -------------------------------------------

    def test_zero_R_rejected(self):
        bad_sig = (
            varint(0)
            + varint(7)
            + u32(2)
            + varint(1)
            + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_zero_signer_count_rejected(self):
        bad_sig = varint(5) + varint(7) + u32(0)
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_declared_signer_count_too_large(self):
        bad_sig = (
            varint(5) + varint(7) + u32(3) + varint(1) + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_declared_signer_count_too_small_trailing(self):
        bad_sig = (
            varint(5)
            + varint(7)
            + u32(1)
            + varint(1)
            + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_zero_signer_id_rejected(self):
        bad_sig = (
            varint(5) + varint(7) + u32(2) + varint(0) + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_increasing_signer_ids_rejected(self):
        bad_sig = (
            varint(5) + varint(7) + u32(2) + varint(3) + varint(1)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_duplicate_signer_ids_rejected(self):
        bad_sig = (
            varint(5) + varint(7) + u32(2) + varint(3) + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_canonical_integer_leading_zero_rejected(self):
        # R encoded with a forbidden leading zero: length 2, body 00 05.
        bad_sig = (
            u32(2)
            + b"\x00\x05"
            + varint(7)
            + u32(2)
            + varint(1)
            + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_canonical_zero_rejected(self):
        # Zero must be the single body byte 00; 00 00 is non-canonical.
        bad_sig = (
            varint(5)
            + u32(2)
            + b"\x00\x00"
            + u32(2)
            + varint(1)
            + varint(3)
        )
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_over_long_varint_length_rejected(self):
        bad_sig = u32(0xFFFFFFFF) + b"\x05"
        bad = wire_with_signature(self.items[:1], bad_sig)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_truncated_signature_frame_rejected(self):
        # Honest framing, then a single dangling byte where R should be.
        bad = WIRE_TAG + seal_framing(self.items[:1]) + b"\x00"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_bare_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(WIRE_TAG)


if __name__ == "__main__":
    unittest.main()
