"""Tests for the canonical transport encoding of the non-empty
order-preserving chain of whole delta report bundle archive seals:
encode_delta_report_bundle_archive_seal_chain /
decode_delta_report_bundle_archive_seal_chain."""

import unittest

from thresholdsign import (
    AggregateSignature,
    AuditProofBundle,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    DeltaReportBundleArchiveSealChain,
    decode_delta_report_bundle_archive_seal,
    decode_delta_report_bundle_archive_seal_chain,
    encode_audit_proof,
    encode_audit_proof_bundle,
    encode_delta_report_bundle_archive,
    encode_delta_report_bundle_archive_seal,
    encode_delta_report_bundle_archive_seal_chain,
    make_proof,
    verify_dc,
)

from test_audit_extension_proof_bundle_codec import make_records
from test_delta_report_bundle_archive_codec import (
    TAG as ARCHIVE_TAG,
    build_archives,
)
from test_delta_report_bundle_archive_seal_codec import make_seal
from test_delta_report_bundle_archive_seal_chain import make_chain

WIRE_TAG = b"ts/drasc/w1"
SEAL_WIRE_TAG = b"ts/dra/w1"
APB_TAG = b"ts/apb/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def signature_frame(signature: AggregateSignature) -> bytes:
    """Independently build the AuditProofBundle signature frame."""
    out = bytearray(varint(signature.R))
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(chain: DeltaReportBundleArchiveSealChain) -> bytes:
    """Independently build the chain wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += u32(len(chain.items))
    for item in chain.items:
        encoded = encode_delta_report_bundle_archive_seal(item)
        out += u32(len(encoded))
        out += encoded
    out += signature_frame(chain.signature)
    return bytes(out)


class EncodeDecodeSealChainTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items_single = (
            make_seal(
                DeltaReportBundleArchive((self.full,)), self.key, seed=1600
            ),
        )
        self.items_many = (
            make_seal(
                DeltaReportBundleArchive((self.full,)), self.key, seed=1610
            ),
            make_seal(
                DeltaReportBundleArchive((self.first, self.second)),
                self.key,
                seed=1611,
            ),
            make_seal(
                DeltaReportBundleArchive(
                    (self.second, self.full, self.first)
                ),
                self.key,
                seed=1612,
            ),
        )
        self.chains = (
            make_chain(self.items_single, self.key, seed=1620),
            make_chain(self.items_many, self.key, seed=1621),
        )

    def test_wire_matches_independent_spec_build(self):
        for chain in self.chains:
            with self.subTest(n=len(chain.items)):
                blob = encode_delta_report_bundle_archive_seal_chain(chain)
                self.assertEqual(blob, build_wire(chain))
                self.assertTrue(blob.startswith(WIRE_TAG))

    def test_wire_layout_is_tag_count_frames_then_signature(self):
        chain = self.chains[1]
        blob = encode_delta_report_bundle_archive_seal_chain(chain)
        offset = 0
        self.assertEqual(blob[offset:len(WIRE_TAG)], WIRE_TAG)
        offset += len(WIRE_TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(chain.items)))
        offset += 4
        for item in chain.items:
            encoded = encode_delta_report_bundle_archive_seal(item)
            self.assertEqual(blob[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(
            blob[offset:], signature_frame(chain.signature)
        )

    def test_outer_signature_frame_matches_audit_proof_bundle_frame(self):
        # The trailing outer signature frame is exactly the frame
        # encode_audit_proof_bundle writes for the same signature.
        chain = self.chains[0]
        records = make_records(self.key, 1)
        _message, proof = make_proof(records, 0)
        bundle = AuditProofBundle(proof, chain.signature)
        bundle_blob = encode_audit_proof_bundle(bundle)
        proof_body = encode_audit_proof(proof)
        bundle_tail = bundle_blob[len(APB_TAG) + 4 + len(proof_body):]

        chain_blob = encode_delta_report_bundle_archive_seal_chain(chain)
        self.assertEqual(chain_blob[-len(bundle_tail):], bundle_tail)

    def test_round_trip_byte_for_byte(self):
        for chain in self.chains:
            with self.subTest(n=len(chain.items)):
                blob = encode_delta_report_bundle_archive_seal_chain(chain)
                restored = decode_delta_report_bundle_archive_seal_chain(blob)
                self.assertIsInstance(
                    restored, DeltaReportBundleArchiveSealChain
                )
                self.assertEqual(restored, chain)
                self.assertEqual(
                    encode_delta_report_bundle_archive_seal_chain(restored),
                    blob,
                )

    def test_nested_seal_frames_decode_standalone(self):
        chain = self.chains[1]
        blob = encode_delta_report_bundle_archive_seal_chain(chain)
        offset = len(WIRE_TAG) + 4
        for item in chain.items:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            frame = blob[offset + 4:offset + 4 + length]
            self.assertEqual(
                decode_delta_report_bundle_archive_seal(bytes(frame)),
                item,
            )
            offset += 4 + length

    def test_order_is_preserved(self):
        forward = make_chain(self.items_many, self.key, seed=1630)
        reverse_items = tuple(reversed(self.items_many))
        reverse = make_chain(reverse_items, self.key, seed=1631)
        restored = decode_delta_report_bundle_archive_seal_chain(
            encode_delta_report_bundle_archive_seal_chain(forward)
        )
        self.assertEqual(restored.items, self.items_many)
        self.assertNotEqual(restored, reverse)
        self.assertEqual(
            decode_delta_report_bundle_archive_seal_chain(
                encode_delta_report_bundle_archive_seal_chain(reverse)
            ).items,
            reverse_items,
        )

    def test_encoding_is_deterministic_and_unique(self):
        chain_a = make_chain(self.items_many, self.key, seed=1640)
        chain_b = make_chain(self.items_many[:2], self.key, seed=1641)
        chain_c = make_chain(
            tuple(reversed(self.items_many)), self.key, seed=1642
        )
        self.assertEqual(
            encode_delta_report_bundle_archive_seal_chain(chain_a),
            encode_delta_report_bundle_archive_seal_chain(chain_a),
        )
        self.assertNotEqual(
            encode_delta_report_bundle_archive_seal_chain(chain_a),
            encode_delta_report_bundle_archive_seal_chain(chain_b),
        )
        self.assertNotEqual(
            encode_delta_report_bundle_archive_seal_chain(chain_a),
            encode_delta_report_bundle_archive_seal_chain(chain_c),
        )

    def test_z_zero_is_structurally_legal_and_round_trips(self):
        # z may be zero and encodes as the single body byte 00; a chain
        # with a structural dummy outer signature carries no verdict but
        # is still a legal structure for the codec.
        chain = DeltaReportBundleArchiveSealChain(
            self.items_single,
            AggregateSignature(R=5, z=0, signer_ids=(1,)),
        )
        blob = encode_delta_report_bundle_archive_seal_chain(chain)
        restored = decode_delta_report_bundle_archive_seal_chain(blob)
        self.assertEqual(restored, chain)
        self.assertEqual(
            encode_delta_report_bundle_archive_seal_chain(restored), blob
        )

    def test_structurally_legal_but_wrong_outer_signature_decodes(self):
        chain = make_chain(self.items_many, self.key, seed=1650)
        blob = bytearray(encode_delta_report_bundle_archive_seal_chain(chain))
        # Flip the last signer-id body byte: still a canonical legal
        # structure, but no longer the signing outer signature.
        blob[-1] ^= 0xFF
        restored = decode_delta_report_bundle_archive_seal_chain(bytes(blob))
        self.assertNotEqual(restored, chain)
        self.assertFalse(verify_dc(restored, self.key))

    def test_decoded_verifying_chain_still_verifies(self):
        chain = make_chain(self.items_many, self.key, seed=1660)
        restored = decode_delta_report_bundle_archive_seal_chain(
            encode_delta_report_bundle_archive_seal_chain(chain)
        )
        self.assertTrue(verify_dc(restored, self.key))


class EncodeSealChainErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            _second,
            _archives,
        ) = build_archives()
        self.items = (
            make_seal(
                DeltaReportBundleArchive((self.full, self.first)),
                self.key,
                seed=1700,
            ),
        )
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_chain_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.items):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_tuple_items_type_error(self):
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(bad, self.signature)
                )

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(
                        (bad,), self.signature
                    )
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(
                        (self.items[0], bad), self.signature
                    )
                )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal_chain(
                DeltaReportBundleArchiveSealChain((), self.signature)
            )

    def test_illegal_nested_seal_value_error(self):
        bad_seal = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()), self.signature
        )
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal_chain(
                DeltaReportBundleArchiveSealChain(
                    (bad_seal,), self.signature
                )
            )
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal_chain(
                DeltaReportBundleArchiveSealChain(
                    (self.items[0], bad_seal), self.signature
                )
            )

    def test_nested_seal_field_type_error(self):
        bad_seal = DeltaReportBundleArchiveSeal(
            "not-an-archive", self.signature
        )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive_seal_chain(
                DeltaReportBundleArchiveSealChain(
                    (bad_seal,), self.signature
                )
            )

    def test_illegal_outer_signature_value_error(self):
        bad_signatures = (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        )
        for bad in bad_signatures:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(self.items, bad)
                )

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal_chain(
                    DeltaReportBundleArchiveSealChain(self.items, bad)
                )


class DecodeSealChainErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            _second,
            _archives,
        ) = build_archives()
        self.items = (
            make_seal(
                DeltaReportBundleArchive((self.full, self.first)),
                self.key,
                seed=1800,
            ),
            make_seal(
                DeltaReportBundleArchive((self.first,)), self.key, seed=1801
            ),
        )
        self.chain = make_chain(self.items, self.key, seed=1802)
        self.blob = encode_delta_report_bundle_archive_seal_chain(self.chain)
        self.frames = [
            encode_delta_report_bundle_archive_seal(item)
            for item in self.items
        ]

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_report_bundle_archive_seal_chain(bad)

    def test_bad_tag(self):
        swap = b"ts/drasc/w0"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                swap + self.blob[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(b"")
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(self.blob[3:])

    def test_zero_item_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG
                + u32(0)
                + signature_frame(self.chain.signature)
            )

    def test_truncated_item_count(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG + self.blob[len(WIRE_TAG):len(WIRE_TAG) + 2]
            )

    def test_zero_or_overlong_seal_frame(self):
        # A zero-length first frame.
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG
                + u32(1)
                + u32(0)
                + signature_frame(self.chain.signature)
            )
        # A declared frame longer than the bytes that follow.
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG
                + u32(1)
                + u32(len(self.frames[0]) + 1)
                + self.frames[0]
                + signature_frame(self.chain.signature)
            )

    def test_item_count_mismatch(self):
        # Count says two items but only one seal frame precedes the
        # outer signature frame, so parsing runs off the end.
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG
                + u32(2)
                + u32(len(self.frames[0]))
                + self.frames[0]
                + signature_frame(self.chain.signature)
            )

    def test_truncation(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(self.blob[:-1])
        # Everything up to but excluding the outer signature frame.
        body_end = len(WIRE_TAG) + 4
        for frame in self.frames:
            body_end += 4 + len(frame)
        self.assertEqual(
            self.blob[body_end:], signature_frame(self.chain.signature)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                self.blob[:body_end + 3]
            )

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                self.blob + b"\x00"
            )

    def test_illegal_nested_seal_frame(self):
        # A nested seal frame that wraps an empty-item archive is
        # rejected by the nested seal decoder even though the outer
        # framing lines up.
        empty_archive = ARCHIVE_TAG + u32(0)
        signature = self.chain.signature
        bad_seal_blob = (
            SEAL_WIRE_TAG
            + u32(len(empty_archive))
            + empty_archive
            + signature_frame(signature)
        )
        bad = (
            WIRE_TAG
            + u32(1)
            + u32(len(bad_seal_blob))
            + bad_seal_blob
            + signature_frame(signature)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_tampered_nested_seal_frame(self):
        tampered = bytearray(self.blob)
        # First seal frame body starts after tag, count and its length.
        tampered[len(WIRE_TAG) + 4 + 4 + 5] ^= 0x01
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bytes(tampered))

    def test_zero_R_is_illegal(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(0)
            + varint(self.chain.signature.z)
            + u32(len(self.chain.signature.signer_ids))
            + b"".join(
                varint(sid) for sid in self.chain.signature.signer_ids
            )
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_canonical_leading_zero_integer(self):
        # Lengthen the outer R body to two bytes with a leading 00.
        prefix = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
        )
        bad = bytearray(
            prefix
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(len(self.chain.signature.signer_ids))
            + b"".join(
                varint(sid) for sid in self.chain.signature.signer_ids
            )
        )
        offset = len(prefix)
        r_body = self.chain.signature.R.to_bytes(
            (self.chain.signature.R.bit_length() + 7) // 8, "big"
        )
        bad[offset:offset + 4 + len(r_body)] = (
            u32(len(r_body) + 1) + b"\x00" + r_body
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bytes(bad))

    def test_zero_signer_count_is_illegal(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_signer_count_mismatch(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(3)
            + b"".join(
                varint(sid) for sid in self.chain.signature.signer_ids
            )
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_non_increasing_signer_ids(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(2)
            + varint(3)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal_chain(
                WIRE_TAG + u32(1) + b"x"
            )


if __name__ == "__main__":
    unittest.main()
