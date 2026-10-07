"""Tests for the cross-receiver DKG public-commitment conflict diagnosis."""

import copy
import dataclasses
import unittest

from thresholdsign import (
    DKGEquivocation,
    DKGReceivedShare,
    DKGView,
    LocalDKGPacket,
    Share,
    create_signing_contribution,
    diagnose_dkg_views,
    export_dkg_view,
)

# Same toy group as the local DKG tests: 8069 = 4 * 2017 + 1 is prime, 16
# and 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def zero_random():
    """Deterministic source that draws only zeros (all-zero polynomials)."""
    return lambda upper: 0


def make_contributions(participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD,
                       seed_offset=0, randbelow=None):
    return [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=randbelow if randbelow is not None else fixed_random(pid + seed_offset),
        )
        for pid in participant_ids
    ]


def packet_for(contribution, receiver_id):
    """The LocalDKGPacket ``receiver_id`` extracts from ``contribution``."""
    dealing = contribution.contribution
    index = dealing.participant_ids.index(receiver_id)
    return LocalDKGPacket(
        participant_ids=dealing.participant_ids,
        received=DKGReceivedShare(
            sender_id=dealing.sender_id,
            receiver_id=receiver_id,
            share=dealing.shares[index],
            blinding_share=dealing.blinding_shares[index],
        ),
        commitment=dealing.commitment,
        feldman_commitment=contribution.feldman_commitment,
    )


def make_views(seed_offset=0, participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD,
               randbelow=None):
    """One honest view per (sender, receiver) pair, nested by sender."""
    contributions = make_contributions(participant_ids, threshold, seed_offset, randbelow)
    return {
        receiver_id: [export_dkg_view(packet_for(c, receiver_id)) for c in contributions]
        for receiver_id in participant_ids
    }


def flat_views(views_by_receiver):
    """All views of every receiver as one flat list."""
    return [view for views in views_by_receiver.values() for view in views]


def sender_views(views_by_receiver, sender_id):
    """The views one sender showed every receiver, as a list."""
    return [
        next(v for v in views if v.sender_id == sender_id)
        for views in views_by_receiver.values()
    ]


class ExportDKGViewTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.packet = packet_for(self.contributions[0], 2)

    def test_view_carries_only_public_fields(self):
        view = export_dkg_view(self.packet)
        self.assertIsInstance(view, DKGView)
        self.assertEqual(
            [field.name for field in dataclasses.fields(view)],
            ["sender_id", "receiver_id", "participant_ids", "commitment",
             "feldman_commitment"],
        )
        self.assertEqual(view.sender_id, 1)
        self.assertEqual(view.receiver_id, 2)
        self.assertEqual(view.participant_ids, PARTICIPANT_IDS)
        self.assertEqual(view.commitment, self.packet.commitment)
        self.assertEqual(view.feldman_commitment, self.packet.feldman_commitment)

    def test_view_is_frozen_and_value_comparable(self):
        view = export_dkg_view(self.packet)
        self.assertEqual(view, export_dkg_view(self.packet))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            view.sender_id = 9

    def test_share_equations_are_not_verified(self):
        received = self.packet.received
        share = received.share
        tampered = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(
                received, share=Share(share.x, (share.y + 1) % FIELD_PRIME)
            ),
        )
        view = export_dkg_view(tampered)
        self.assertEqual(view.commitment, self.packet.commitment)

    def test_zero_shares_and_identity_commitments(self):
        contributions = make_contributions(randbelow=zero_random())
        view = export_dkg_view(packet_for(contributions[0], 2))
        self.assertEqual(view.commitment.values, (1, 1))

    def test_non_packet_raises_type_error(self):
        for bad in ("packet", 7, None, True, self.packet.received):
            with self.assertRaises(TypeError, msg=repr(bad)):
                export_dkg_view(bad)

    def test_field_type_errors(self):
        packet = self.packet
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, participant_ids=[1, 2, 3]))
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, participant_ids=(1, 2, True)))
        with self.assertRaises(TypeError):
            export_dkg_view(
                dataclasses.replace(
                    packet,
                    received=dataclasses.replace(packet.received, sender_id=True),
                )
            )
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, commitment="c"))
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, feldman_commitment=None))

    def test_structure_errors_raise_value_error(self):
        packet = self.packet
        for broken in (
            dataclasses.replace(packet, participant_ids=()),
            dataclasses.replace(packet, participant_ids=(2, 1, 3)),
            dataclasses.replace(packet, participant_ids=(0, 1, 2)),
            dataclasses.replace(
                packet, received=dataclasses.replace(packet.received, sender_id=4)
            ),
            dataclasses.replace(
                packet, received=dataclasses.replace(packet.received, receiver_id=4)
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(packet.commitment, values=(1,)),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(packet.commitment, values=(0, 1)),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(broken)):
                export_dkg_view(broken)

    def test_input_not_mutated(self):
        packet = self.packet
        snapshot = copy.deepcopy(packet)
        export_dkg_view(packet)
        self.assertEqual(packet, snapshot)


class DiagnoseDKGViewsCleanTest(unittest.TestCase):
    def test_honest_views_return_empty_tuple(self):
        result = diagnose_dkg_views(flat_views(make_views()))
        self.assertEqual(result, ())
        self.assertIsInstance(result, tuple)

    def test_accepts_single_pass_iterator(self):
        views = flat_views(make_views())
        self.assertEqual(diagnose_dkg_views(iter(views)), ())
        self.assertEqual(diagnose_dkg_views(v for v in views), ())

    def test_input_order_does_not_matter(self):
        views = flat_views(make_views())
        forward = diagnose_dkg_views(views)
        self.assertEqual(diagnose_dkg_views(list(reversed(views))), forward)
        shuffled = [views[2], views[0], views[5], views[1], views[4], views[3]]
        self.assertEqual(diagnose_dkg_views(shuffled), forward)

    def test_partial_membership_views_are_allowed(self):
        views = make_views()
        # Only sender 2's claims, and only as shown to receivers 1 and 3.
        subset = [
            next(v for v in views[1] if v.sender_id == 2),
            next(v for v in views[3] if v.sender_id == 2),
        ]
        self.assertEqual(diagnose_dkg_views(subset), ())

    def test_single_view_per_sender_produces_no_records(self):
        views = make_views()
        self.assertEqual(diagnose_dkg_views([views[2][0]]), ())

    def test_different_senders_are_never_compared(self):
        # Two senders with different commitments, one view each: legal.
        views = make_views()
        self.assertEqual(diagnose_dkg_views([views[1][0], views[1][1]]), ())

    def test_threshold_one_and_identity_commitments(self):
        self.assertEqual(
            diagnose_dkg_views(flat_views(make_views(threshold=1))), ()
        )
        self.assertEqual(
            diagnose_dkg_views(flat_views(make_views(randbelow=zero_random()))), ()
        )

    def test_invalid_shares_still_diagnose_clean(self):
        # The diagnosis compares public claims only: views exported from
        # packets whose shares fail verification stay conflict-free.
        contributions = make_contributions()
        views = []
        for receiver_id in PARTICIPANT_IDS:
            packet = packet_for(contributions[0], receiver_id)
            received = packet.received
            share = received.share
            tampered = dataclasses.replace(
                packet,
                received=dataclasses.replace(
                    received, share=Share(share.x, (share.y + 1) % FIELD_PRIME)
                ),
            )
            views.append(export_dkg_view(tampered))
        self.assertEqual(diagnose_dkg_views(views), ())


class DiagnoseDKGViewsConflictTest(unittest.TestCase):
    def setUp(self):
        self.views = make_views()
        # A second, independent batch: same group and threshold, different
        # commitments for every sender.
        self.other = make_views(seed_offset=100)

    def replace_commitments(self, view, donor, pedersen=True, feldman=True):
        changes = {}
        if pedersen:
            changes["commitment"] = donor.commitment
        if feldman:
            changes["feldman_commitment"] = donor.feldman_commitment
        return dataclasses.replace(view, **changes)

    def test_pedersen_only_conflict(self):
        honest = sender_views(self.views, 1)
        donor = sender_views(self.other, 1)[1]
        bad = self.replace_commitments(honest[1], donor, feldman=False)
        result = diagnose_dkg_views([honest[0], bad, honest[2]])
        self.assertEqual(
            result,
            (
                DKGEquivocation(1, (1, 2), "pedersen"),
                DKGEquivocation(1, (2, 3), "pedersen"),
            ),
        )

    def test_feldman_only_conflict(self):
        honest = sender_views(self.views, 2)
        donor = sender_views(self.other, 2)[0]
        bad = self.replace_commitments(honest[0], donor, pedersen=False)
        result = diagnose_dkg_views([bad, honest[1], honest[2]])
        self.assertEqual(
            result,
            (
                DKGEquivocation(2, (1, 2), "feldman"),
                DKGEquivocation(2, (1, 3), "feldman"),
            ),
        )

    def test_both_checks_conflict_pedersen_first(self):
        honest = sender_views(self.views, 3)
        donor = sender_views(self.other, 3)[2]
        bad = self.replace_commitments(honest[2], donor)
        result = diagnose_dkg_views([honest[0], honest[1], bad])
        self.assertEqual(
            result,
            (
                DKGEquivocation(3, (1, 3), "pedersen"),
                DKGEquivocation(3, (1, 3), "feldman"),
                DKGEquivocation(3, (2, 3), "pedersen"),
                DKGEquivocation(3, (2, 3), "feldman"),
            ),
        )

    def test_all_three_receivers_shown_different_commitments(self):
        honest = sender_views(self.views, 1)
        donors = sender_views(self.other, 1)
        batch = [
            honest[0],
            self.replace_commitments(honest[1], donors[1], feldman=False),
            self.replace_commitments(honest[2], donors[2], feldman=False),
        ]
        # donors[1] and donors[2] come from the same sender of one honest
        # batch, so they agree with each other but not with honest[0].
        result = diagnose_dkg_views(batch)
        self.assertEqual(
            result,
            (
                DKGEquivocation(1, (1, 2), "pedersen"),
                DKGEquivocation(1, (1, 3), "pedersen"),
            ),
        )

    def test_records_sorted_by_sender_then_receiver_pair(self):
        first = sender_views(self.views, 1)
        third = sender_views(self.views, 3)
        donors_first = sender_views(self.other, 1)
        donors_third = sender_views(self.other, 3)
        batch = [
            self.replace_commitments(third[2], donors_third[2]),
            first[0],
            self.replace_commitments(first[1], donors_first[1]),
            third[0],
            first[2],
            third[1],
        ]
        result = diagnose_dkg_views(batch)
        self.assertEqual(
            result,
            (
                DKGEquivocation(1, (1, 2), "pedersen"),
                DKGEquivocation(1, (1, 2), "feldman"),
                DKGEquivocation(1, (2, 3), "pedersen"),
                DKGEquivocation(1, (2, 3), "feldman"),
                DKGEquivocation(3, (1, 3), "pedersen"),
                DKGEquivocation(3, (1, 3), "feldman"),
                DKGEquivocation(3, (2, 3), "pedersen"),
                DKGEquivocation(3, (2, 3), "feldman"),
            ),
        )

    def test_conflicts_across_receivers_of_a_partial_sender_set(self):
        # Only sender 2's claims from receivers 1 and 3 conflict; no view
        # of any other sender is needed for the diagnosis.
        honest = sender_views(self.views, 2)
        donor = sender_views(self.other, 2)[2]
        bad = self.replace_commitments(honest[2], donor, pedersen=False)
        result = diagnose_dkg_views([honest[0], bad])
        self.assertEqual(result, (DKGEquivocation(2, (1, 3), "feldman"),))

    def test_equivocation_carries_only_public_fields(self):
        honest = sender_views(self.views, 1)
        donor = sender_views(self.other, 1)[0]
        bad = self.replace_commitments(honest[0], donor)
        (record,) = diagnose_dkg_views([bad, honest[1]])[:1]
        self.assertEqual(
            [field.name for field in dataclasses.fields(record)],
            ["sender_id", "receiver_ids", "check"],
        )
        self.assertEqual(record.receiver_ids, (1, 2))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.check = "none"


class DiagnoseDKGViewsValidationTest(unittest.TestCase):
    def setUp(self):
        self.views = flat_views(make_views())

    def test_non_iterable_views(self):
        for bad in (7, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_dkg_views(bad)

    def test_non_view_elements(self):
        for bad in ("view", 7, self.views[0].commitment, self.views):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_dkg_views([bad])

    def test_field_type_errors(self):
        view = self.views[0]
        for broken in (
            dataclasses.replace(view, sender_id=True),
            dataclasses.replace(view, receiver_id="2"),
            dataclasses.replace(view, participant_ids=[1, 2, 3]),
            dataclasses.replace(view, participant_ids=(1, 2, False)),
            dataclasses.replace(view, commitment=view.feldman_commitment),
            dataclasses.replace(view, feldman_commitment=view.commitment),
            dataclasses.replace(
                view,
                commitment=dataclasses.replace(view.commitment, values=[1, 1]),
            ),
            dataclasses.replace(
                view,
                commitment=dataclasses.replace(
                    view.commitment, blinding_generator=True
                ),
            ),
            dataclasses.replace(
                view,
                feldman_commitment=dataclasses.replace(
                    view.feldman_commitment, values=(1, "x")
                ),
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(broken)):
                diagnose_dkg_views([broken])

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            diagnose_dkg_views([])

    def test_duplicate_sender_receiver_pair_rejected_even_when_identical(self):
        view = self.views[0]
        with self.assertRaises(ValueError):
            diagnose_dkg_views([view, view])
        with self.assertRaises(ValueError):
            diagnose_dkg_views([view, dataclasses.replace(view)])

    def test_view_structure_errors(self):
        view = self.views[0]
        for broken in (
            dataclasses.replace(view, participant_ids=()),
            dataclasses.replace(view, participant_ids=(2, 1, 3)),
            dataclasses.replace(view, participant_ids=(1, 2, FIELD_PRIME)),
            dataclasses.replace(view, sender_id=4),
            dataclasses.replace(view, receiver_id=0),
            dataclasses.replace(
                view, commitment=dataclasses.replace(view.commitment, values=())
            ),
            dataclasses.replace(
                view,
                commitment=dataclasses.replace(view.commitment, values=(1,) * 4),
                feldman_commitment=dataclasses.replace(
                    view.feldman_commitment, values=(1,) * 4
                ),
            ),
            dataclasses.replace(
                view,
                feldman_commitment=dataclasses.replace(
                    view.feldman_commitment,
                    values=view.feldman_commitment.values + (1,),
                ),
            ),
            dataclasses.replace(
                view,
                feldman_commitment=dataclasses.replace(
                    view.feldman_commitment, generator=BLINDING_GENERATOR
                ),
            ),
            dataclasses.replace(
                view,
                commitment=dataclasses.replace(view.commitment, field_prime=4),
            ),
            dataclasses.replace(
                view,
                commitment=dataclasses.replace(view.commitment, values=(2, 1)),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(broken)):
                diagnose_dkg_views([broken])

    def test_views_disagree_on_participant_ids(self):
        other = flat_views(make_views(participant_ids=(1, 2, 4)))
        with self.assertRaises(ValueError):
            diagnose_dkg_views([self.views[0], other[0]])

    def test_views_disagree_on_threshold(self):
        other = flat_views(make_views(threshold=3))
        with self.assertRaises(ValueError):
            diagnose_dkg_views([self.views[0], other[0]])

    def test_views_disagree_on_group_parameters(self):
        view = self.views[0]
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            view,
            commitment=dataclasses.replace(
                view.commitment, blinding_generator=4096
            ),
        )
        with self.assertRaises(ValueError):
            diagnose_dkg_views([self.views[1], moved])

    def test_structural_error_rejects_whole_call_without_partial_diagnosis(self):
        # A conflicting pair plus a structurally illegal view must raise,
        # never return the conflict records.
        honest = sender_views(make_views(), 1)
        donor = sender_views(make_views(seed_offset=100), 1)[0]
        bad = dataclasses.replace(honest[0], commitment=donor.commitment)
        illegal = dataclasses.replace(honest[1], participant_ids=())
        with self.assertRaises(ValueError):
            diagnose_dkg_views([bad, honest[2], illegal])

    def test_input_not_mutated(self):
        views = flat_views(make_views())
        snapshot = copy.deepcopy(views)
        diagnose_dkg_views(views)
        self.assertEqual(views, snapshot)
        with self.assertRaises(ValueError):
            diagnose_dkg_views([views[0], views[0]])
        self.assertEqual(views, snapshot)


if __name__ == "__main__":
    unittest.main()
