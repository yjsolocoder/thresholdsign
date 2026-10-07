"""Tests for the cross-receiver DKG view export and equivocation diagnoser."""

import copy
import dataclasses
import unittest

from thresholdsign import (
    DKGEquivocation,
    DKGReceivedShare,
    DKGView,
    FeldmanCommitment,
    LocalDKGPacket,
    PedersenCommitment,
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


def make_contributions(participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD, randbelow=None):
    return [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=randbelow if randbelow is not None else fixed_random(pid),
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


def make_views(participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD, randbelow=None):
    """One exported view per (sender, receiver) pair of a fresh DKG round."""
    contributions = make_contributions(participant_ids, threshold, randbelow)
    return [
        export_dkg_view(packet_for(contribution, receiver_id))
        for receiver_id in participant_ids
        for contribution in contributions
    ]


def views_for(sender_id, views):
    return [view for view in views if view.sender_id == sender_id]


class ExportDKGViewTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.packet = packet_for(self.contributions[0], 2)

    def test_view_carries_only_the_public_fields(self):
        view = export_dkg_view(self.packet)
        self.assertEqual(
            [field.name for field in dataclasses.fields(view)],
            [
                "sender_id",
                "receiver_id",
                "participant_ids",
                "commitment",
                "feldman_commitment",
            ],
        )
        self.assertEqual(
            view,
            DKGView(
                sender_id=1,
                receiver_id=2,
                participant_ids=PARTICIPANT_IDS,
                commitment=self.packet.commitment,
                feldman_commitment=self.packet.feldman_commitment,
            ),
        )

    def test_view_is_frozen_and_compared_by_value(self):
        view = export_dkg_view(self.packet)
        self.assertEqual(view, export_dkg_view(self.packet))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            view.sender_id = 3
        self.assertEqual(
            view,
            DKGView(1, 2, PARTICIPANT_IDS, view.commitment, view.feldman_commitment),
        )

    def test_share_equations_are_not_verified(self):
        received = self.packet.received
        share = received.share
        tampered = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(
                received, share=Share(share.x, (share.y + 1) % FIELD_PRIME)
            ),
        )
        self.assertEqual(export_dkg_view(tampered), export_dkg_view(self.packet))

    def test_zero_shares_and_identity_commitments(self):
        contributions = make_contributions(randbelow=zero_random())
        view = export_dkg_view(packet_for(contributions[0], 2))
        self.assertEqual(view.commitment.values, (1, 1))
        self.assertEqual(view.feldman_commitment.values, (1, 1))

    def test_non_packet_argument(self):
        for bad in ("packet", 7, None, True, self.packet.received):
            with self.assertRaises(TypeError, msg=repr(bad)):
                export_dkg_view(bad)

    def test_field_type_errors(self):
        packet = self.packet
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, participant_ids=[1, 2, 3]))
        with self.assertRaises(TypeError):
            export_dkg_view(
                dataclasses.replace(packet, participant_ids=(1, 2, True))
            )
        broken_received = dataclasses.replace(packet.received, sender_id=2.0)
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, received=broken_received))
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, commitment="c"))
        with self.assertRaises(TypeError):
            export_dkg_view(dataclasses.replace(packet, feldman_commitment=None))

    def test_structural_errors_raise_value_error(self):
        packet = self.packet
        broken_received = dataclasses.replace(packet.received, sender_id=4)
        with self.assertRaises(ValueError):
            export_dkg_view(dataclasses.replace(packet, received=broken_received))
        broken_received = dataclasses.replace(packet.received, receiver_id=4)
        with self.assertRaises(ValueError):
            export_dkg_view(dataclasses.replace(packet, received=broken_received))
        with self.assertRaises(ValueError):
            export_dkg_view(
                dataclasses.replace(
                    packet,
                    feldman_commitment=dataclasses.replace(
                        packet.feldman_commitment,
                        values=packet.feldman_commitment.values + (1,),
                    ),
                )
            )

    def test_input_unchanged_and_no_state_between_calls(self):
        packet = self.packet
        snapshot = copy.deepcopy(packet)
        first = export_dkg_view(packet)
        second = export_dkg_view(packet)
        self.assertEqual(packet, snapshot)
        self.assertEqual(first, second)


class DiagnoseDKGViewsCleanTest(unittest.TestCase):
    def test_consistent_round_returns_empty_tuple(self):
        records = diagnose_dkg_views(make_views())
        self.assertEqual(records, ())
        self.assertIsInstance(records, tuple)

    def test_accepts_single_pass_iterator(self):
        self.assertEqual(diagnose_dkg_views(iter(make_views())), ())
        again = (view for view in make_views())
        self.assertEqual(diagnose_dkg_views(again), ())

    def test_input_order_does_not_matter(self):
        views = make_views()
        forward = diagnose_dkg_views(views)
        self.assertEqual(diagnose_dkg_views(list(reversed(views))), forward)
        shuffled = [views[4], views[0], views[8], views[2]] + [
            view
            for index, view in enumerate(views)
            if index not in (0, 2, 4, 8)
        ]
        self.assertEqual(diagnose_dkg_views(shuffled), forward)

    def test_partial_views_are_allowed(self):
        views = make_views()
        subset = [
            views_for(1, views)[0],
            views_for(1, views)[1],
            views_for(2, views)[2],
        ]
        self.assertEqual(diagnose_dkg_views(subset), ())

    def test_single_view_per_sender_produces_no_record(self):
        views = make_views()
        self.assertEqual(
            diagnose_dkg_views([views_for(1, views)[0], views_for(2, views)[0]]),
            (),
        )

    def test_threshold_one_and_zero_secret_rounds(self):
        self.assertEqual(diagnose_dkg_views(make_views(threshold=1)), ())
        self.assertEqual(diagnose_dkg_views(make_views(randbelow=zero_random())), ())

    def test_single_participant(self):
        self.assertEqual(
            diagnose_dkg_views(make_views(participant_ids=(5,), threshold=1)), ()
        )


class DiagnoseDKGViewsEquivocationTest(unittest.TestCase):
    def setUp(self):
        self.views = make_views()

    def tamper_pedersen(self, view):
        """Give one view a different, structurally legal Pedersen commitment."""
        other = next(v for v in self.views if v.sender_id != view.sender_id)
        return dataclasses.replace(
            view,
            commitment=dataclasses.replace(
                view.commitment, values=other.commitment.values
            ),
        )

    def tamper_feldman(self, view):
        """Give one view a different, structurally legal Feldman commitment."""
        other = next(v for v in self.views if v.sender_id != view.sender_id)
        return dataclasses.replace(
            view,
            feldman_commitment=dataclasses.replace(
                view.feldman_commitment,
                values=other.feldman_commitment.values,
            ),
        )

    def sender_views(self, sender_id):
        return views_for(sender_id, self.views)

    def test_pedersen_conflict_only(self):
        sender_one = self.sender_views(1)
        bad = self.tamper_pedersen(sender_one[0])  # receiver 1
        batch = [bad, sender_one[1], sender_one[2], *views_for(2, self.views)]
        records = diagnose_dkg_views(batch)
        self.assertEqual(
            records,
            (
                DKGEquivocation(1, (1, 2), "pedersen"),
                DKGEquivocation(1, (1, 3), "pedersen"),
            ),
        )

    def test_feldman_conflict_only(self):
        sender_two = self.sender_views(2)
        bad = self.tamper_feldman(sender_two[2])  # receiver 3
        batch = [*sender_two[:2], bad, *self.sender_views(1)]
        records = diagnose_dkg_views(batch)
        self.assertEqual(
            records,
            (
                DKGEquivocation(2, (1, 3), "feldman"),
                DKGEquivocation(2, (2, 3), "feldman"),
            ),
        )

    def test_both_kinds_conflict_pedersen_first(self):
        sender_three = self.sender_views(3)
        view = sender_three[1]  # receiver 2
        bad = dataclasses.replace(
            self.tamper_pedersen(view),
            feldman_commitment=self.tamper_feldman(view).feldman_commitment,
        )
        records = diagnose_dkg_views([sender_three[0], bad, sender_three[2]])
        self.assertEqual(
            records,
            (
                DKGEquivocation(3, (1, 2), "pedersen"),
                DKGEquivocation(3, (1, 2), "feldman"),
                DKGEquivocation(3, (2, 3), "pedersen"),
                DKGEquivocation(3, (2, 3), "feldman"),
            ),
        )

    def test_every_pair_of_receivers_is_compared(self):
        sender_one = self.sender_views(1)
        # Receiver 2's view of sender 1 conflicts on both kinds.
        view = sender_one[1]
        bad = dataclasses.replace(
            self.tamper_pedersen(view),
            feldman_commitment=self.tamper_feldman(view).feldman_commitment,
        )
        records = diagnose_dkg_views([bad, sender_one[0], sender_one[2]])
        self.assertEqual(
            records,
            (
                DKGEquivocation(1, (1, 2), "pedersen"),
                DKGEquivocation(1, (1, 2), "feldman"),
                DKGEquivocation(1, (2, 3), "pedersen"),
                DKGEquivocation(1, (2, 3), "feldman"),
            ),
        )

    def test_records_sorted_by_sender_then_receiver_pair(self):
        sender_one = self.sender_views(1)
        sender_three = self.sender_views(3)
        bad_one = self.tamper_pedersen(sender_one[2])
        bad_three = self.tamper_feldman(sender_three[0])
        batch = [
            bad_three, sender_three[1], sender_three[2],
            bad_one, sender_one[1], sender_one[0],
        ]
        expected = (
            DKGEquivocation(1, (1, 3), "pedersen"),
            DKGEquivocation(1, (2, 3), "pedersen"),
            DKGEquivocation(3, (1, 2), "feldman"),
            DKGEquivocation(3, (1, 3), "feldman"),
        )
        self.assertEqual(diagnose_dkg_views(batch), expected)
        self.assertEqual(diagnose_dkg_views(list(reversed(batch))), expected)

    def test_senders_are_never_compared_with_each_other(self):
        # Every sender's commitments differ from every other sender's by
        # construction; with one view per sender there is nothing to report.
        views = [self.sender_views(pid)[0] for pid in PARTICIPANT_IDS]
        self.assertEqual(diagnose_dkg_views(views), ())

    def test_partial_views_still_report_conflicts(self):
        sender_two = self.sender_views(2)
        bad = self.tamper_pedersen(sender_two[0])  # receiver 1
        # Only receivers 1 and 3 submitted a view of sender 2.
        records = diagnose_dkg_views([bad, sender_two[2]])
        self.assertEqual(records, (DKGEquivocation(2, (1, 3), "pedersen"),))

    def test_equivocation_record_fields(self):
        record = DKGEquivocation(2, (1, 3), "pedersen")
        self.assertEqual(
            [field.name for field in dataclasses.fields(record)],
            ["sender_id", "receiver_ids", "check"],
        )
        self.assertEqual(record, DKGEquivocation(2, (1, 3), "pedersen"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.check = "feldman"


class DiagnoseDKGViewsValidationTest(unittest.TestCase):
    def setUp(self):
        self.views = make_views()

    def test_non_iterable_argument(self):
        for bad in (7, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_dkg_views(bad)

    def test_non_view_elements(self):
        for bad in ("view", 7, self.views[0].commitment, self.views):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_dkg_views([bad])

    def test_field_type_errors(self):
        view = self.views[0]
        with self.assertRaises(TypeError):
            diagnose_dkg_views([dataclasses.replace(view, sender_id=True)])
        with self.assertRaises(TypeError):
            diagnose_dkg_views([dataclasses.replace(view, receiver_id="2")])
        with self.assertRaises(TypeError):
            diagnose_dkg_views(
                [dataclasses.replace(view, participant_ids=[1, 2, 3])]
            )
        with self.assertRaises(TypeError):
            diagnose_dkg_views(
                [dataclasses.replace(view, participant_ids=(1, 2, False))]
            )
        with self.assertRaises(TypeError):
            diagnose_dkg_views([dataclasses.replace(view, commitment="c")])
        with self.assertRaises(TypeError):
            diagnose_dkg_views([dataclasses.replace(view, feldman_commitment=None)])
        broken_commitment = dataclasses.replace(
            view.commitment, values=list(view.commitment.values)
        )
        with self.assertRaises(TypeError):
            diagnose_dkg_views(
                [dataclasses.replace(view, commitment=broken_commitment)]
            )
        broken_commitment = dataclasses.replace(
            view.commitment, values=(True,) + view.commitment.values[1:]
        )
        with self.assertRaises(TypeError):
            diagnose_dkg_views(
                [dataclasses.replace(view, commitment=broken_commitment)]
            )
        broken_feldman = dataclasses.replace(view.feldman_commitment, generator=1.5)
        with self.assertRaises(TypeError):
            diagnose_dkg_views(
                [dataclasses.replace(view, feldman_commitment=broken_feldman)]
            )

    def test_empty_input(self):
        with self.assertRaises(ValueError):
            diagnose_dkg_views([])

    def test_duplicate_sender_receiver_pair_rejected_even_when_identical(self):
        view = self.views[0]
        with self.assertRaises(ValueError):
            diagnose_dkg_views([view, view])
        twin = DKGView(
            view.sender_id,
            view.receiver_id,
            view.participant_ids,
            view.commitment,
            view.feldman_commitment,
        )
        self.assertEqual(view, twin)
        with self.assertRaises(ValueError):
            diagnose_dkg_views([view, twin, self.views[1]])

    def test_views_disagree_on_participant_ids(self):
        other = make_views(participant_ids=(1, 2, 4))
        with self.assertRaises(ValueError):
            diagnose_dkg_views([self.views[0], other[0]])

    def test_views_disagree_on_threshold(self):
        other = make_views(threshold=3)
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

    def test_structural_value_errors(self):
        view = self.views[0]
        for broken in (
            dataclasses.replace(view, participant_ids=()),
            dataclasses.replace(view, participant_ids=(2, 1, 3)),
            dataclasses.replace(view, participant_ids=(0, 1, 2)),
            dataclasses.replace(view, participant_ids=(1, 2, FIELD_PRIME)),
            dataclasses.replace(view, sender_id=4),
            dataclasses.replace(view, receiver_id=4),
        ):
            with self.assertRaises(ValueError, msg=repr(broken)):
                diagnose_dkg_views([broken])

    def test_threshold_and_commitment_value_errors(self):
        view = self.views[0]
        commitment = view.commitment
        feldman = view.feldman_commitment
        empty = dataclasses.replace(
            view,
            commitment=dataclasses.replace(commitment, values=()),
            feldman_commitment=dataclasses.replace(feldman, values=()),
        )
        with self.assertRaises(ValueError):
            diagnose_dkg_views([empty])
        too_long = (1,) * 4
        over = dataclasses.replace(
            view,
            commitment=dataclasses.replace(commitment, values=too_long),
            feldman_commitment=dataclasses.replace(feldman, values=too_long),
        )
        with self.assertRaises(ValueError):
            diagnose_dkg_views([over])
        mismatched = dataclasses.replace(
            view,
            feldman_commitment=dataclasses.replace(
                feldman, values=feldman.values + (1,)
            ),
        )
        with self.assertRaises(ValueError):
            diagnose_dkg_views([mismatched])
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                view,
                commitment=dataclasses.replace(
                    commitment, values=(bad_value,) + commitment.values[1:]
                ),
            )
            with self.assertRaises(ValueError, msg=repr(bad_value)):
                diagnose_dkg_views([broken])

    def test_illegal_group_parameters(self):
        view = self.views[0]
        commitment = view.commitment
        feldman = view.feldman_commitment
        for broken_commitment in (
            dataclasses.replace(commitment, field_prime=4),
            dataclasses.replace(commitment, generator=1),
            dataclasses.replace(commitment, blinding_generator=GENERATOR),
        ):
            broken = dataclasses.replace(
                view,
                commitment=broken_commitment,
                feldman_commitment=dataclasses.replace(
                    feldman,
                    field_prime=broken_commitment.field_prime,
                    group_prime=broken_commitment.group_prime,
                    generator=broken_commitment.generator,
                ),
            )
            with self.assertRaises(ValueError):
                diagnose_dkg_views([broken])

    def test_structural_error_rejects_whole_call_without_partial_records(self):
        # A conflicting (reportable) view plus a structurally illegal view
        # must raise, never return the conflict records.
        sender_one = [
            view for view in self.views if view.sender_id == 1
        ]
        other = next(view for view in self.views if view.sender_id == 2)
        bad = dataclasses.replace(
            sender_one[0],
            commitment=dataclasses.replace(
                sender_one[0].commitment, values=other.commitment.values
            ),
        )
        illegal = dataclasses.replace(sender_one[2], participant_ids=())
        with self.assertRaises(ValueError):
            diagnose_dkg_views([bad, sender_one[1], illegal])


class DiagnoseDKGViewsNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.views = make_views()

    def test_input_unchanged_on_success(self):
        views = self.views
        snapshot = copy.deepcopy(views)
        diagnose_dkg_views(views)
        self.assertEqual(views, snapshot)

    def test_input_unchanged_with_conflicts(self):
        sender_one = [view for view in self.views if view.sender_id == 1]
        other = self.views[-1]
        bad = dataclasses.replace(
            sender_one[0],
            commitment=dataclasses.replace(
                sender_one[0].commitment, values=other.commitment.values
            ),
        )
        views = [bad, *sender_one[1:]]
        snapshot = copy.deepcopy(views)
        diagnose_dkg_views(views)
        self.assertEqual(views, snapshot)

    def test_input_unchanged_on_value_error(self):
        views = [self.views[0], self.views[0]]
        snapshot = copy.deepcopy(views)
        with self.assertRaises(ValueError):
            diagnose_dkg_views(views)
        self.assertEqual(views, snapshot)

    def test_no_state_between_calls(self):
        views = self.views
        first = diagnose_dkg_views(views)
        self.assertEqual(diagnose_dkg_views(views), first)
        self.assertEqual(diagnose_dkg_views(list(reversed(views))), first)


if __name__ == "__main__":
    unittest.main()
