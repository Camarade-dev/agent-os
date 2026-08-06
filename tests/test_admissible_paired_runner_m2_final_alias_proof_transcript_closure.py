"""M2 final alias-proof / exact-commit transcript closure.

Each finding is closed by making the untrue statement impossible to produce.

M2-B63 -- a discharge names the authority that actually proves it
    ``_drain_within`` selected a group canonical for each exact resource, and a
    later drain whose canonical published nothing could still discharge its alias
    from a terminal result *another* drain had published.  The row then read

        alias_of                        = REGISTERED:2
        canonical_result.canonical_label = UNREGISTERED:1
        state                           = DISCHARGED_BY_THE_CANONICAL_OBLIGATION...

    The resource really was discharged; the evidence credited the discharge to an
    obligation that had proved nothing.  Four facts are now kept apart and every
    row carries all four -- the group canonical selected here, the obligation
    whose result actually proves the discharge, which publication of that result
    was read, and where the proof came from -- with a closed origin set.  A
    result published elsewhere discharges under its own label and generation and
    is reported as ``RESOURCE_DISCHARGED_BY_PUBLISHED_RESULT_FOR_SAME_IDENTITY``;
    an alias whose own exact observation proves absence is reported as an own
    observation and is never called a canonical discharge.  The row guard refuses
    every mismatched attribution where the row is built.

M2-M64 -- the repository describes the evidence it actually carries
    The current artifacts declared ``full_transcript_bytes = 173972``,
    ``full_transcript_sha256`` over those bytes and ``transcript_available =
    true`` while carrying a 29-byte summary and nothing else, and a provenance
    sentence claiming the embedded value was "complete bytes".  No such object
    existed anywhere in the repository.

    Repository truth and external audit evidence are now separated.  A commit
    cannot contain the transcript of a run performed against that same commit, so
    the current artifacts record the starting commit's qualification as history,
    this pass's precommit qualification of the *uncommitted worktree* as
    implementer evidence, and the exact external evidence contract as pending --
    and they claim no bytes they do not carry.  The exact-commit transcript and
    receipt are produced outside the repository after the single commit and are
    bound to it by hash.

Deterministic tests drive the real process cleanup registry, the real published
canonical result table and real descriptors.  Delegated physical tests run the
production path inside a real ``Delegate=yes`` cgroup v2 subtree and, under
``ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1``, fail rather than skip.

Nothing here contacts a provider, a model, a transport, a policy engine, an
owner authority, a broker, a mint, a witness, or a network.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.paired_runner import private_workspace as pw  # noqa: E402
from admissible.paired_runner import process_ownership as po  # noqa: E402
from admissible.paired_runner import process_supervision as ps  # noqa: E402
from admissible.paired_runner import resource_limits as rl  # noqa: E402
from admissible.paired_runner.process_ownership import (  # noqa: E402
    CHILD_SUBREAPER,
    Deadline,
)
from admissible.paired_runner.resource_limits import probe_cgroup_delegation  # noqa: E402

DELEGATION = probe_cgroup_delegation()
REQUIRE_DELEGATED = os.environ.get("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP") == "1"

from _paired_runner_m2_fixtures import (  # noqa: E402
    guard_process_wide_cgroup_caches,
    guard_process_wide_cleanup_registry,
    guard_process_wide_restoration_debt,
    guard_process_wide_subreaper_ownership,
)
from admissible.paired_runner.sandbox import probe_capsule_readiness  # noqa: E402

CAPSULE_READY = probe_capsule_readiness()

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = REPOSITORY_ROOT / "implementation"

BRANCH = "paired-runner/m2-final-alias-proof-transcript-closure"
STARTING_COMMIT = "90a33c610b58900fc40f617de1508f4192dc03d1"
STARTING_COMMIT_PARENT = "6d687d4c778ae917f925da18aa89b2c53cdac911"
INDEPENDENT_AUDIT_SHA256 = (
    "85e28e4e590e6ee2e59075192eb37d95c16962804a26fc4d92eaa9ef0f90a7c2"
)
INDEPENDENT_AUDIT_VERDICTS = (
    "M2_ALIAS_CAPACITY_ARTIFACT_TCB_FINAL_INDEPENDENT_CLOSURE_REFUSED",
    "MILESTONE_3_NOT_PERMITTED",
)
CLOSURE_KEY = "m2_final_alias_proof_transcript_closure"
CLOSURE_REPORT = IMPLEMENTATION / "M2_FINAL_ALIAS_PROOF_TRANSCRIPT_CLOSURE_REPORT.json"
VALIDATION_REPORT = IMPLEMENTATION / "M2_VALIDATION_REPORT.json"
REQUIREMENT_MATRIX = IMPLEMENTATION / "PAIRED_RUNNER_REQUIREMENT_MATRIX.json"
PRIOR_CLOSURE_REPORT = IMPLEMENTATION / "M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_REPORT.json"
THIS_MODULE = "tests.test_admissible_paired_runner_m2_final_alias_proof_transcript_closure"
#: The ten modules the delegated qualification of this closure must run.
QUALIFICATION_MODULES = (
    "tests.test_admissible_paired_runner_m2_b25_cgroup_topology",
    "tests.test_admissible_paired_runner_m2_b25_final_failclosed",
    "tests.test_admissible_paired_runner_m2_final_protocol_lifecycle",
    "tests.test_admissible_paired_runner_m2_subreaper_deadline_closure",
    "tests.test_admissible_paired_runner_m2_ownership_debt_reap_closure",
    "tests.test_admissible_paired_runner_m2_process_owner_cleanup_propagation_closure",
    "tests.test_admissible_paired_runner_m2_cgroup_identity_reap_registry_serialization_closure",
    "tests.test_admissible_paired_runner_m2_exact_removal_global_drain_reservation_provenance_closure",
    "tests.test_admissible_paired_runner_m2_alias_capacity_artifact_tcb_closure",
    THIS_MODULE,
)
#: The delegated result of the *starting* commit.  History, never a
#: qualification of the revision this closure produces.
HISTORICAL_STARTING_COMMIT_RESULT = "Ran 746 tests in 338.649s\n\nOK"
#: The exact unsupported claim M2-M64 withdraws.  It may appear in a current
#: artifact only inside the record of its own withdrawal.
WITHDRAWN_FULL_TRANSCRIPT_BYTES = 173972
WITHDRAWN_FULL_TRANSCRIPT_SHA256 = (
    "313d725e0450b4af33e1c516f5842afef8925bd30b59cbff1b2a075da3956d35"
)
#: Keys that assert bytes.  A current artifact may carry them only over bytes it
#: actually contains.
TRANSCRIPT_CLAIM_KEYS = (
    "transcript_available",
    "full_transcript_bytes",
    "full_transcript_sha256",
)
EXACT_COMMIT_TRANSCRIPT_TEMPLATE = (
    "PAIRED_RUNNER_M2_FINAL_EXACT_COMMIT_DELEGATED_TRANSCRIPT_<commit>.txt"
)
EXACT_COMMIT_RECEIPT_TEMPLATE = (
    "PAIRED_RUNNER_M2_FINAL_EXACT_COMMIT_DELEGATED_RECEIPT_<commit>.json"
)
REQUIRED_RECEIPT_FIELDS = (
    "repository_path",
    "branch",
    "commit",
    "parent",
    "bounded_range_count",
    "worktree_clean",
    "command",
    "mode",
    "modules",
    "environment",
    "exit_code",
    "transcript_bytes",
    "transcript_sha256",
    "ran_line",
    "final_status",
    "skipped",
    "failures",
    "errors",
    "started_at",
    "ended_at",
)

RETRY_BUDGET_MS = 5_000


def delegated(test):
    """Physical qualification.  Never skipped under the no-false-green variable."""

    if REQUIRE_DELEGATED:
        return test
    return unittest.skipUnless(
        DELEGATION.available,
        f"no delegated cgroup v2 topology on this host: {DELEGATION.detail}",
    )(test)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _effect_cgroups(parent: Path) -> list[Path]:
    return sorted(parent.glob(f"{rl.EFFECT_PREFIX}*"))


def _walk(node, path="") -> list[tuple[str, dict]]:
    """Every dictionary in a document, with the path that reaches it."""

    found: list[tuple[str, dict]] = []
    if isinstance(node, dict):
        found.append((path or "/", node))
        for key, value in node.items():
            found.extend(_walk(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_walk(value, f"{path}[{index}]"))
    return found


# --- process-wide guards -------------------------------------------------------


def guard_process_wide_unregistered_cleanups(test: unittest.TestCase) -> None:
    """Discharge and restore the process-level registrar-failure collection."""

    saved = list(rl._UNREGISTERED_CLEANUPS)
    saved_pid = rl._UNREGISTERED_OWNER_PID
    saved_ledger = dict(pw._LAST_DRAIN_LEDGER)

    def restore() -> None:
        try:
            for _attempt in range(4):
                added = [
                    handle
                    for handle in rl.unregistered_cleanups()
                    if all(handle is not existing for existing in saved)
                ]
                if not added:
                    break
                for handle in added:
                    try:
                        handle.settle_cleanup(
                            deadline=Deadline.after_ms(RETRY_BUDGET_MS, "teardown")
                        )
                    except Exception:  # pragma: no cover - the guard masks nothing
                        pass
                    if getattr(handle, "cleanup_complete", False):
                        rl._release_unregistered(handle)
        finally:
            rl._UNREGISTERED_CLEANUPS[:] = saved
            rl._UNREGISTERED_OWNER_PID = saved_pid
            pw._LAST_DRAIN_LEDGER = saved_ledger

    test.addCleanup(restore)


def guard_process_wide_canonical_results(test: unittest.TestCase) -> None:
    """Restore the process-wide published canonical results (M2-B59/M2-B63).

    A test that publishes a terminal result puts back what it found, so it
    neither discharges another test's alias nor is discharged by another test's
    result -- which is exactly the attribution this module is about.
    """

    saved = dict(pw._CANONICAL_RESULTS)
    saved_generation = pw._CANONICAL_RESULT_GENERATION

    def restore() -> None:
        pw._CANONICAL_RESULTS.clear()
        pw._CANONICAL_RESULTS.update(saved)
        pw._CANONICAL_RESULT_GENERATION = saved_generation

    test.addCleanup(restore)


class _ProcessGuard:
    """Put back every process-wide fact a test in this module can disturb."""

    @staticmethod
    def install(test: unittest.TestCase) -> int:
        before, error = po.get_child_subreaper()
        test.assertIsNone(error, "this kernel does not expose PR_GET_CHILD_SUBREAPER")
        guard_process_wide_restoration_debt(test)
        guard_process_wide_subreaper_ownership(test)
        guard_process_wide_cleanup_registry(test)
        guard_process_wide_unregistered_cleanups(test)
        guard_process_wide_canonical_results(test)

        def restore() -> None:
            po.set_child_subreaper(int(before or 0))

        test.addCleanup(restore)
        return int(before or 0)


# --- one exact resource, several obligations ----------------------------------


class _SharedResource:
    """One underlying resource named by more than one obligation."""

    def __init__(self, identity: str) -> None:
        self.identity = identity
        self.outstanding = True
        self.destructive_primitives = 0


class _SharedResourceObligation:
    """A retained obligation naming an exact resource identity by construction."""

    def __init__(
        self,
        name: str,
        resource: _SharedResource,
        *,
        settles: bool = True,
        registration_outstanding: bool = False,
    ) -> None:
        self.name = name
        self.resource = resource
        self.settles = settles
        #: The M2-B57 shape: the resource is discharged and only the registry
        #: entry the registrar refused is still owed.
        self.registration_outstanding = registration_outstanding
        self._registry_id: str | None = None
        self.attempts = 0
        self.grants: list[int] = []

    @property
    def identity(self) -> str:
        return self.resource.identity

    def settle_cleanup(self, *, deadline: Deadline | None = None) -> dict:
        self.attempts += 1
        self.grants.append(0 if deadline is None else int(deadline.remaining_seconds * 1000))
        if self.settles and self.resource.outstanding:
            self.resource.destructive_primitives += 1
            self.resource.outstanding = False
        return {"name": self.name, "granted_ms": self.grants[-1]}

    def cleanup_evidence(self) -> dict:
        outstanding = self.resource.outstanding
        complete = not outstanding and not self.registration_outstanding
        return {
            "kind": "EFFECT_CGROUP",
            "effect_path": f"/fixture/{self.name}",
            "owned_identity": self.identity,
            "containment_settled": not outstanding,
            "process_obligations_complete": True,
            "resource_outstanding": outstanding,
            "outstanding_work": (
                (rl.OUTSTANDING_CONTAINMENT,)
                if outstanding
                else ((rl.OUTSTANDING_REGISTRATION,) if not complete else (rl.OUTSTANDING_NOTHING,))
            ),
            "cleanup_complete": complete,
            "cleanup_retryable": not complete,
            "cleanup_retry_operation": (
                rl.CGROUP_RETRY_REMOVE
                if outstanding
                else (rl.CGROUP_RETRY_RECORD if not complete else rl.CGROUP_RETRY_NONE)
            ),
            "settlement_attempts": self.attempts,
            "helper_pid": 0,
        }

    def evidence(self) -> dict:
        return self.cleanup_evidence()


class _AliasProofFixture(unittest.TestCase):
    """The construction the attribution tests share."""

    def setUp(self) -> None:
        _ProcessGuard.install(self)
        patcher = mock.patch.object(pw, "CLEANUP_DRAIN_TOTAL_DEADLINE_MS", 400)
        patcher.start()
        self.addCleanup(patcher.stop)

    def retain(self, handle) -> None:
        rl._retain_unregistered(handle)
        self.addCleanup(rl._release_unregistered, handle)

    def register(self, handle) -> str | None:
        return pw._CLEANUP_REGISTRY.record(handle, handle.evidence())

    def claim_elsewhere(self, entry) -> None:
        """Another drain owns this entry for the duration of the test."""

        entry.claimed_by = threading.get_ident() + 1
        self.addCleanup(setattr, entry, "claimed_by", None)

    def drain(self, ms: int = 2_000) -> list[dict]:
        return pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(ms, "proof"))

    def publish_from_another_obligation(self, identity: str) -> pw._CanonicalResult:
        """Settle the resource once, under an obligation of its own label.

        The publication is real: the obligation is drained, it is the canonical
        obligation for that exact identity, and the terminal result it publishes
        is the one every later drain reads.
        """

        resource = _SharedResource(identity)
        source = _SharedResourceObligation("published-source", resource)
        rl._retain_unregistered(source)
        try:
            rows = self.drain()
        finally:
            rl._release_unregistered(source)
        self.assertEqual([row["alias_of"] for row in rows], [None], rows)
        published = pw._published_canonical_result(identity)
        self.assertIsNotNone(published, "the terminal result was not published")
        return published

    @staticmethod
    def split(rows: list[dict]) -> tuple[list[dict], list[dict]]:
        canonical = [row for row in rows if row["alias_of"] is None]
        aliases = [row for row in rows if row["alias_of"] is not None]
        return canonical, aliases


# --- M2-B63: the claim names the authority that proves it ----------------------


class DischargeProofAttributionTests(_AliasProofFixture):
    """Every positive discharge row identifies the exact proving authority."""

    def test_the_current_canonical_is_named_when_it_is_the_proof(self) -> None:
        resource = _SharedResource("63:01")
        canonical = _SharedResourceObligation("canonical", resource)
        alias = _SharedResourceObligation("alias", resource)
        self.retain(canonical)
        self.retain(alias)
        canonical_rows, aliases = self.split(self.drain())
        row = aliases[0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertEqual(
            row["discharge_proof_origin"],
            pw.DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL,
        )
        # The three labels agree, which is exactly what makes this state legal.
        self.assertEqual(row["group_canonical_label"], canonical_rows[0]["label"])
        self.assertEqual(row["discharge_proof_source_label"], row["group_canonical_label"])
        self.assertEqual(
            row["discharge_proof_source_label"], row["canonical_result"]["canonical_label"]
        )
        self.assertEqual(
            row["discharge_proof_generation"],
            row["canonical_result"]["publication_generation"],
        )
        self.assertEqual(row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_ALIAS)
        self.assertEqual(row["granted_ms"], 0, "an alias spent a second grant")
        self.assertEqual(resource.destructive_primitives, 1)

    def test_a_canonical_claimed_elsewhere_with_no_publication_proves_nothing(self) -> None:
        resource = _SharedResource("63:02")
        canonical = _SharedResourceObligation("canonical", resource)
        alias = _SharedResourceObligation("alias", resource)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        rows = self.drain()
        self.assertEqual([row["collection"] for row in rows], ["UNREGISTERED"], rows)
        row = rows[0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertEqual(row["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGIN_NONE)
        self.assertIsNone(row["discharge_proof_source_label"])
        self.assertIsNone(row["discharge_proof_generation"])
        self.assertTrue(row["resource_outstanding"])
        self.assertTrue(resource.outstanding)
        self.assertEqual(alias.attempts, 0, "a retained alias ran a settlement")

    def test_a_terminal_result_from_another_cleanup_is_named_as_the_source(self) -> None:
        """The audited row: the group canonical is not what proved it."""

        published = self.publish_from_another_obligation("63:03")
        resource = _SharedResource("63:03")
        resource.outstanding = False
        canonical = _SharedResourceObligation(
            "canonical", resource, registration_outstanding=True
        )
        alias = _SharedResourceObligation("alias", resource, registration_outstanding=True)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        rows = self.drain()
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT)
        self.assertEqual(
            row["discharge_proof_origin"],
            pw.DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT,
        )
        self.assertEqual(row["discharge_proof_source_label"], published.label)
        self.assertEqual(row["discharge_proof_generation"], published.generation)
        self.assertEqual(row["unattempted_reason"], pw.DRAIN_UNATTEMPTED_PUBLISHED_RESULT)
        # The exact defect: the row must not credit the group's canonical.
        self.assertNotEqual(
            row["discharge_proof_source_label"],
            row["group_canonical_label"],
            "the published result was credited to the canonical selected here",
        )
        self.assertNotEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertEqual(row["granted_ms"], 0)

    def test_a_prior_publication_is_named_with_its_own_label_and_generation(self) -> None:
        published = self.publish_from_another_obligation("63:04")
        # Two further drains happen before the one that reads it, so the
        # generation named cannot be "the newest thing that happened".
        self.publish_from_another_obligation("63:04:other-a")
        self.publish_from_another_obligation("63:04:other-b")
        resource = _SharedResource("63:04")
        resource.outstanding = False
        canonical = _SharedResourceObligation(
            "canonical", resource, registration_outstanding=True
        )
        alias = _SharedResourceObligation("alias", resource, registration_outstanding=True)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        row = self.drain()[0]
        self.assertEqual(row["discharge_proof_source_label"], published.label)
        self.assertEqual(row["discharge_proof_generation"], published.generation)
        self.assertLess(
            row["discharge_proof_generation"],
            pw._CANONICAL_RESULT_GENERATION,
            "the row named the newest generation rather than the one that proved it",
        )

    def test_a_published_result_for_another_identity_discharges_nothing(self) -> None:
        self.publish_from_another_obligation("63:05:elsewhere")
        resource = _SharedResource("63:05")
        canonical = _SharedResourceObligation("canonical", resource, settles=False)
        alias = _SharedResourceObligation("alias", resource, settles=False)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        row = self.drain()[0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertEqual(row["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGIN_NONE)
        self.assertTrue(resource.outstanding)

    def test_an_own_exact_observation_is_a_distinct_authority(self) -> None:
        """Absence proved by the alias itself is never a canonical discharge."""

        resource = _SharedResource("63:06")
        resource.outstanding = False
        canonical = _SharedResourceObligation(
            "canonical", resource, registration_outstanding=True
        )
        alias = _SharedResourceObligation("alias", resource, registration_outstanding=True)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        row = self.drain()[0]
        self.assertEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_OWN_OBSERVATION)
        self.assertEqual(
            row["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGIN_OWN_POSITIVE_OBSERVATION
        )
        self.assertEqual(row["discharge_proof_source_label"], row["label"])
        self.assertIsNone(row["discharge_proof_generation"])
        self.assertNotEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertFalse(row["resource_outstanding"])
        self.assertEqual(row["granted_ms"], 0, "an own observation spent a grant")

    def test_a_publication_replaced_after_the_lookup_is_still_named_exactly(self) -> None:
        """The row names the result it read, not the table's latest state."""

        published = self.publish_from_another_obligation("63:07")
        replacement = pw._CanonicalResult(
            resource_identity="63:07", label="REPLACEMENT:999", generation=10**6
        )
        replacement.publish(
            {
                "attempted": True,
                "granted_ms": 1,
                "cleanup_complete": True,
                "resource_outstanding": False,
                "retained": False,
                "state": pw.DRAIN_STATE_ATTEMPTED,
            }
        )
        real_lookup = pw._published_canonical_result

        def replacing(identity: str):
            result = real_lookup(identity)
            if identity == "63:07":
                # Another drain publishes a newer terminal result for the same
                # exact resource between the lookup and the row construction.
                pw._CANONICAL_RESULTS["63:07"] = replacement
            return result

        resource = _SharedResource("63:07")
        resource.outstanding = False
        canonical = _SharedResourceObligation(
            "canonical", resource, registration_outstanding=True
        )
        alias = _SharedResourceObligation("alias", resource, registration_outstanding=True)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        with mock.patch.object(pw, "_published_canonical_result", replacing):
            row = self.drain()[0]
        self.assertIs(pw._CANONICAL_RESULTS["63:07"], replacement, "the swap did not happen")
        self.assertEqual(row["discharge_proof_source_label"], published.label)
        self.assertEqual(row["discharge_proof_generation"], published.generation)
        self.assertNotEqual(row["discharge_proof_source_label"], replacement.label)
        self.assertNotEqual(row["discharge_proof_generation"], replacement.generation)

    def test_repeated_drains_preserve_one_truthful_proof_source(self) -> None:
        resource = _SharedResource("63:08")
        canonical = _SharedResourceObligation("canonical", resource, settles=False)
        alias = _SharedResourceObligation("alias", resource, settles=False)
        self.retain(canonical)
        self.retain(alias)
        _canonical_rows, aliases = self.split(self.drain())
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertEqual(aliases[0]["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGIN_NONE)
        canonical.settles = True
        alias.settles = True
        sources = []
        for _round in range(3):
            canonical_rows, aliases = self.split(self.drain())
            sources.append(
                (
                    aliases[0]["state"],
                    aliases[0]["discharge_proof_origin"],
                    aliases[0]["discharge_proof_source_label"] == canonical_rows[0]["label"],
                )
            )
        self.assertEqual(
            set(sources),
            {
                (
                    pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
                    pw.DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL,
                    True,
                )
            },
            sources,
        )
        self.assertEqual(resource.destructive_primitives, 1)

    def test_the_ledger_counts_the_three_authorities_separately(self) -> None:
        resource = _SharedResource("63:09")
        canonical = _SharedResourceObligation("canonical", resource)
        alias = _SharedResourceObligation("alias", resource)
        self.retain(canonical)
        self.retain(alias)
        self.drain()
        ledger = pw.cleanup_drain_ledger()
        self.assertEqual(ledger["aliases_identified"], 1)
        self.assertEqual(ledger["aliases_discharged_by_a_canonical_obligation"], 1)
        self.assertEqual(ledger["aliases_discharged_by_a_published_result"], 0)
        self.assertEqual(ledger["aliases_discharged_by_their_own_observation"], 0)
        self.assertIn(
            pw.DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL, ledger["discharge_proof_origins"]
        )
        for entry in ledger["order"]:
            with self.subTest(sequence=entry["sequence"]):
                self.assertIn(entry["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGINS)

    def test_every_row_carries_a_proof_origin_from_the_closed_set(self) -> None:
        outstanding = _SharedResource("63:10")
        settled = _SharedResource("63:11")
        handles = [
            _SharedResourceObligation("outstanding", outstanding, settles=False),
            _SharedResourceObligation("outstanding-alias", outstanding, settles=False),
            _SharedResourceObligation("settled", settled),
            _SharedResourceObligation("settled-alias", settled),
        ]
        for handle in handles:
            self.retain(handle)
        for row in self.drain():
            with self.subTest(label=row["label"]):
                self.assertIn(row["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGINS)
                if row["state"] in pw.DRAIN_STATES_POSITIVE_DISCHARGE:
                    self.assertNotEqual(
                        row["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGIN_NONE
                    )
                    self.assertTrue(row["discharge_proof_source_label"])
                    self.assertFalse(row["resource_outstanding"])
                else:
                    self.assertNotIn(row["state"], pw.DRAIN_STATES_POSITIVE_DISCHARGE)


class DischargeProofRowGuardTests(unittest.TestCase):
    """The row guard refuses every mismatched attribution where it is built."""

    @staticmethod
    def result(
        identity: str = "1:2",
        *,
        label: str = "UNREGISTERED:1",
        generation: int = 7,
        published: bool = True,
        outstanding: bool = False,
        state: str = pw.DRAIN_STATE_ATTEMPTED,
    ) -> pw._CanonicalResult:
        result = pw._CanonicalResult(
            resource_identity=identity, label=label, generation=generation
        )
        if published:
            result.published = True
            result.state = state
            result.resource_outstanding = outstanding
        return result

    @staticmethod
    def row(**overrides) -> dict:
        base = {
            "state": pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT,
            "attempted": False,
            "granted_ms": 0,
            "label": "UNREGISTERED:3",
            "alias_of": "REGISTERED:2",
            "group_canonical_label": "REGISTERED:2",
            "discharge_proof_source_label": "UNREGISTERED:1",
            "discharge_proof_generation": 7,
            "discharge_proof_origin": pw.DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT,
            "unattempted_reason": pw.DRAIN_UNATTEMPTED_PUBLISHED_RESULT,
            "resource_outstanding": False,
            "resource_identity": "1:2",
            "effect_cgroup_path": "/fixture/alias",
        }
        base.update(overrides)
        return base

    def refuses(self, row: dict, result: pw._CanonicalResult | None) -> str:
        with self.assertRaises(pw.DrainEvidenceContradiction) as caught:
            pw._guard_drain_row(row, canonical_result=result)
        return str(caught.exception)

    def test_a_coherent_published_result_discharge_is_accepted(self) -> None:
        row = pw._guard_drain_row(self.row(), canonical_result=self.result())
        self.assertEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT)

    def test_a_current_canonical_state_with_a_foreign_source_is_refused(self) -> None:
        """The audited misattribution, refused where the row is built."""

        detail = self.refuses(
            self.row(
                state=pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
                unattempted_reason=pw.DRAIN_UNATTEMPTED_ALIAS,
                discharge_proof_origin=pw.DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL,
            ),
            self.result(),
        )
        self.assertIn("credits its discharge to the group canonical", detail)

    def test_a_current_canonical_state_with_a_foreign_generation_is_refused(self) -> None:
        self.refuses(
            self.row(
                state=pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
                unattempted_reason=pw.DRAIN_UNATTEMPTED_ALIAS,
                discharge_proof_origin=pw.DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL,
                alias_of="UNREGISTERED:1",
                group_canonical_label="UNREGISTERED:1",
                discharge_proof_generation=999,
            ),
            self.result(),
        )

    def test_a_current_canonical_state_with_a_published_result_origin_is_refused(self) -> None:
        self.refuses(
            self.row(
                state=pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
                unattempted_reason=pw.DRAIN_UNATTEMPTED_ALIAS,
                alias_of="UNREGISTERED:1",
                group_canonical_label="UNREGISTERED:1",
            ),
            self.result(),
        )

    def test_a_published_result_state_without_a_source_label_is_refused(self) -> None:
        self.refuses(self.row(discharge_proof_source_label=None), self.result())

    def test_a_published_result_state_without_a_generation_is_refused(self) -> None:
        detail = self.refuses(self.row(discharge_proof_generation=None), self.result())
        self.assertIn("without naming it", detail)

    def test_a_published_result_state_naming_the_wrong_publication_is_refused(self) -> None:
        self.refuses(self.row(discharge_proof_generation=6), self.result())
        self.refuses(self.row(discharge_proof_source_label="SOMEBODY:9"), self.result())

    def test_a_published_result_for_another_identity_is_refused(self) -> None:
        self.refuses(self.row(), self.result(identity="9:9"))

    def test_an_unpublished_or_nonterminal_source_result_is_refused(self) -> None:
        self.refuses(self.row(), None)
        self.refuses(self.row(), self.result(published=False))
        self.refuses(self.row(), self.result(outstanding=True))
        for state in (
            pw.DRAIN_STATE_UNRESOLVED,
            pw.DRAIN_STATE_RETAINED_UNATTEMPTED,
            pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL,
            pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT,
        ):
            with self.subTest(source_state=state):
                self.refuses(self.row(), self.result(state=state))

    def test_a_published_result_state_over_an_outstanding_resource_is_refused(self) -> None:
        detail = self.refuses(self.row(resource_outstanding=True), self.result())
        self.assertIn("still outstanding", detail)

    def test_an_own_observation_without_a_positive_observation_is_refused(self) -> None:
        own = {
            "state": pw.DRAIN_STATE_DISCHARGED_BY_OWN_OBSERVATION,
            "unattempted_reason": pw.DRAIN_UNATTEMPTED_RESOURCE_DISCHARGED,
            "discharge_proof_origin": pw.DISCHARGE_PROOF_ORIGIN_OWN_POSITIVE_OBSERVATION,
            "discharge_proof_source_label": "UNREGISTERED:3",
            "discharge_proof_generation": None,
        }
        pw._guard_drain_row(self.row(**own))
        self.refuses(self.row(**{**own, "resource_outstanding": True}), None)
        self.refuses(self.row(**{**own, "discharge_proof_source_label": "SOMEBODY:1"}), None)
        self.refuses(self.row(**{**own, "discharge_proof_generation": 7}), None)
        self.refuses(
            self.row(
                **{
                    **own,
                    "discharge_proof_origin": (
                        pw.DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT
                    ),
                }
            ),
            None,
        )

    def test_a_positive_state_naming_no_authority_is_refused(self) -> None:
        for state in pw.DRAIN_STATES_POSITIVE_DISCHARGE:
            with self.subTest(state=state):
                self.refuses(
                    self.row(
                        state=state,
                        unattempted_reason=pw._DRAIN_STATE_REASONS[state],
                        discharge_proof_origin=pw.DISCHARGE_PROOF_ORIGIN_NONE,
                        discharge_proof_source_label=None,
                        discharge_proof_generation=None,
                    ),
                    self.result(),
                )

    def test_a_retained_alias_naming_a_proof_is_refused(self) -> None:
        self.refuses(
            self.row(
                state=pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL,
                unattempted_reason=pw.DRAIN_UNATTEMPTED_CANONICAL_UNRESOLVED,
                resource_outstanding=True,
            ),
            None,
        )

    def test_prose_that_disagrees_with_the_structured_fields_is_refused(self) -> None:
        detail = self.refuses(
            self.row(unattempted_reason=pw.DRAIN_UNATTEMPTED_ALIAS), self.result()
        )
        self.assertIn("describes a different authority", detail)

    def test_an_unknown_proof_origin_is_refused(self) -> None:
        detail = self.refuses(
            self.row(
                state=pw.DRAIN_STATE_UNRESOLVED,
                unattempted_reason=None,
                discharge_proof_origin="INVENTED",
            ),
            None,
        )
        self.assertIn("unknown discharge proof origin", detail)

    def test_the_origin_set_is_closed_and_the_positive_states_are_declared(self) -> None:
        self.assertEqual(
            set(pw.DISCHARGE_PROOF_ORIGINS),
            {
                "CURRENT_DRAIN_CANONICAL",
                "OTHER_DRAIN_PUBLISHED_RESULT",
                "OWN_POSITIVE_OBSERVATION",
                "NONE",
            },
        )
        self.assertEqual(
            set(pw.DRAIN_STATES_POSITIVE_DISCHARGE),
            {
                pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL,
                pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT,
                pw.DRAIN_STATE_DISCHARGED_BY_OWN_OBSERVATION,
                pw.DRAIN_STATE_RESOURCE_DISCHARGED,
            },
        )
        for state in pw.DRAIN_STATES:
            with self.subTest(state=state):
                self.assertIn(state, pw._DRAIN_STATE_REASONS)


class DischargeProofSerializationTests(_AliasProofFixture):
    """Attribution survives serialization exactly, or it is not evidence."""

    def test_a_row_and_its_ledger_round_trip_without_losing_attribution(self) -> None:
        published = self.publish_from_another_obligation("63:12")
        resource = _SharedResource("63:12")
        resource.outstanding = False
        canonical = _SharedResourceObligation(
            "canonical", resource, registration_outstanding=True
        )
        alias = _SharedResourceObligation("alias", resource, registration_outstanding=True)
        self.register(canonical)
        self.retain(alias)
        self.claim_elsewhere(pw._CLEANUP_REGISTRY.pending()[0])
        row = self.drain()[0]
        restored = json.loads(json.dumps(row, sort_keys=True))
        for field in (
            "state",
            "label",
            "alias_of",
            "group_canonical_label",
            "discharge_proof_source_label",
            "discharge_proof_generation",
            "discharge_proof_origin",
            "unattempted_reason",
        ):
            with self.subTest(field=field):
                self.assertEqual(restored[field], row[field])
        self.assertEqual(restored["discharge_proof_source_label"], published.label)
        ledger = json.loads(json.dumps(pw.cleanup_drain_ledger(), sort_keys=True))
        entry = ledger["order"][0]
        self.assertEqual(entry["discharge_proof_source_label"], published.label)
        self.assertEqual(entry["discharge_proof_generation"], published.generation)
        self.assertEqual(
            entry["discharge_proof_origin"],
            pw.DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT,
        )
        self.assertNotEqual(
            entry["discharge_proof_source_label"], entry["group_canonical_label"]
        )
        # The registry's published ledger carries the same attribution.
        published_ledger = pw.cleanup_registry_evidence()["last_drain"]
        self.assertEqual(published_ledger["order"], pw.cleanup_drain_ledger()["order"])


class ProductionWiringTests(unittest.TestCase):
    """The production code carries the closure, not just the tests."""

    def setUp(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        self.private_workspace = (package / "private_workspace.py").read_text(encoding="utf-8")

    def body(self, marker: str) -> str:
        return self.private_workspace.split(marker)[1].split("\ndef ")[0]

    def test_the_origin_is_decided_where_the_result_is_selected(self) -> None:
        body = self.body("def _drain_within")
        self.assertIn("proof_origin = DISCHARGE_PROOF_ORIGIN_CURRENT_DRAIN_CANONICAL", body)
        self.assertIn(
            "proof_origin = DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT", body
        )
        self.assertIn("proof_origin = DISCHARGE_PROOF_ORIGIN_NONE", body)

    def test_the_classifier_names_the_result_it_was_given(self) -> None:
        body = self.body("def _classify_drain_row")
        self.assertIn("canonical_result.label", body)
        self.assertIn("canonical_result.generation", body)
        self.assertIn("DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT", body)
        self.assertIn("DRAIN_STATE_DISCHARGED_BY_OWN_OBSERVATION", body)
        # The origin is a fact carried from the selection site, never a guess
        # made here by comparing two labels that may coincide.
        self.assertNotIn("canonical_result.label == alias_of", body)
        self.assertNotIn("alias_of == canonical_result.label", body)

    def test_the_guard_refuses_a_mismatched_source_label(self) -> None:
        body = self.body("def _guard_drain_row")
        self.assertIn("source != group_label or source != canonical_result.label", body)
        self.assertIn("generation != canonical_result.generation", body)
        self.assertIn("DRAIN_STATES_POSITIVE_DISCHARGE", body)
        self.assertIn("_DRAIN_STATE_REASONS[state]", body)

    def test_both_row_builders_publish_the_same_four_fields(self) -> None:
        for marker in ("    def drain_entry(", "def _drain_unregistered_obligation"):
            with self.subTest(builder=marker.strip()):
                body = self.private_workspace.split(marker)[1].split("\n    def ")[0]
                self.assertIn("**proof,", body)
                self.assertIn('"label": label,', body)


# --- M2-M64: the repository describes the evidence it carries ------------------


def _exact_commit_refusals(
    contract: dict,
    *,
    transcript: Path | None,
    receipt: Path | None,
    commit: str,
    parent: str,
) -> list[str]:
    """The bundle rule, executed.

    The final audit bundle receives the two external paths, verifies their hashes
    and their binding to the exact commit, and carries both as first-class
    manifest members.  This is that verification, run against real files so the
    contract is executable rather than declarative.
    """

    refusals: list[str] = []
    for name, path in (("transcript", transcript), ("receipt", receipt)):
        if path is None or not path.is_file():
            refusals.append(f"EVIDENCE_ABSENT:{name}")
        elif path.stat().st_size == 0:
            refusals.append(f"EVIDENCE_EMPTY:{name}")
    if refusals:
        return refusals
    raw = transcript.read_bytes()
    try:
        record = json.loads(receipt.read_text(encoding="utf-8"))
    except ValueError:
        return ["RECEIPT_UNPARSEABLE"]
    for field in contract["required_receipt_fields"]:
        if field not in record:
            refusals.append(f"RECEIPT_FIELD_MISSING:{field}")
    if refusals:
        return refusals
    if record["transcript_sha256"] != hashlib.sha256(raw).hexdigest():
        refusals.append("TRANSCRIPT_HASH_MISMATCH")
    if record["transcript_bytes"] != len(raw):
        refusals.append("TRANSCRIPT_BYTE_COUNT_MISMATCH")
    if record["commit"] != commit:
        refusals.append("RECEIPT_COMMIT_MISMATCH")
    if record["parent"] != parent:
        refusals.append("RECEIPT_PARENT_MISMATCH")
    if record["bounded_range_count"] != 1:
        refusals.append("RECEIPT_BOUNDED_RANGE_NOT_ONE")
    if not record["worktree_clean"]:
        refusals.append("RECEIPT_WORKTREE_NOT_CLEAN")
    if sorted(record["modules"]) != sorted(contract["required_modules"]):
        refusals.append("RECEIPT_MODULES_INCOMPLETE")
    required = contract["required_result"]
    if (
        record["final_status"] != required["result"]
        or record["exit_code"] != 0
        or record["skipped"] != required["skipped"]
        or record["failures"] != required["failures"]
        or record["errors"] != required["errors"]
    ):
        refusals.append("RECEIPT_NOT_A_CLEAN_RUN")
    if contract["transcript_filename_template"].replace("<commit>", commit) != transcript.name:
        refusals.append("TRANSCRIPT_FILENAME_NOT_BOUND_TO_THE_COMMIT")
    if contract["receipt_filename_template"].replace("<commit>", commit) != receipt.name:
        refusals.append("RECEIPT_FILENAME_NOT_BOUND_TO_THE_COMMIT")
    return refusals


class CurrentArtifactTranscriptTruthTests(unittest.TestCase):
    """A current artifact claims no bytes the repository does not carry."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.validation = _load(VALIDATION_REPORT)
        cls.closure = _load(REPOSITORY_ROOT / cls.validation["final_repair_report"])
        cls.documents = {
            "validation": cls.validation,
            cls.validation["final_repair_report"]: cls.closure,
        }

    def nodes(self):
        for name, document in self.documents.items():
            for path, node in _walk(document):
                yield f"{name}{path}", node

    def test_the_withdrawn_claim_is_exactly_what_it_was(self) -> None:
        """The 29 bytes that were described as 173972."""

        self.assertEqual(len(HISTORICAL_STARTING_COMMIT_RESULT.encode("utf-8")), 29)
        self.assertEqual(
            hashlib.sha256(HISTORICAL_STARTING_COMMIT_RESULT.encode("utf-8")).hexdigest(),
            "0be808a28a99750d54ad81e5e45bed470ac3780f766f315bd3dce9caacbbaaa3",
        )
        self.assertNotEqual(
            len(HISTORICAL_STARTING_COMMIT_RESULT.encode("utf-8")),
            WITHDRAWN_FULL_TRANSCRIPT_BYTES,
        )

    def test_no_current_object_claims_a_transcript_it_does_not_carry(self) -> None:
        for name, node in self.nodes():
            with self.subTest(node=name):
                if node.get("transcript_available"):
                    embedded = node.get("transcript")
                    self.assertIsInstance(embedded, str, f"{name} claims an absent transcript")
                    declared = node.get("full_transcript_bytes")
                    self.assertEqual(
                        len(embedded.encode("utf-8")),
                        declared,
                        f"{name} claims {declared!r} bytes and carries "
                        f"{len(embedded.encode('utf-8'))}",
                    )

    def test_no_current_object_hashes_or_counts_bytes_that_are_absent(self) -> None:
        for name, node in self.nodes():
            with self.subTest(node=name):
                for key in ("full_transcript_bytes", "full_transcript_sha256"):
                    if key not in node:
                        continue
                    embedded = node.get("transcript")
                    self.assertIsInstance(
                        embedded, str, f"{name} declares {key} over absent bytes"
                    )
                    raw = embedded.encode("utf-8")
                    if key == "full_transcript_bytes":
                        self.assertEqual(node[key], len(raw), name)
                    else:
                        self.assertEqual(node[key], hashlib.sha256(raw).hexdigest(), name)

    def test_every_declared_hash_and_count_is_over_bytes_that_are_present(self) -> None:
        for name, node in self.nodes():
            for key, value in node.items():
                if key.endswith("_sha256") and isinstance(value, str):
                    subject = node.get(key[: -len("_sha256")])
                    if isinstance(subject, str):
                        with self.subTest(node=name, field=key):
                            self.assertEqual(
                                hashlib.sha256(subject.encode("utf-8")).hexdigest(), value
                            )
                if key.endswith("_bytes") and isinstance(value, int):
                    subject = node.get(key[: -len("_bytes")])
                    if isinstance(subject, str):
                        with self.subTest(node=name, field=key):
                            self.assertEqual(len(subject.encode("utf-8")), value)

    def test_the_withdrawn_byte_count_appears_only_in_its_own_withdrawal(self) -> None:
        for name, document in self.documents.items():
            with self.subTest(document=name):
                text = json.dumps(document, sort_keys=True)
                if str(WITHDRAWN_FULL_TRANSCRIPT_BYTES) in text:
                    withdrawn = json.dumps(document.get("withdrawn_claims"), sort_keys=True)
                    self.assertIn(
                        str(WITHDRAWN_FULL_TRANSCRIPT_BYTES),
                        withdrawn,
                        f"{name} repeats the withdrawn byte count outside its withdrawal",
                    )
                    self.assertIn(WITHDRAWN_FULL_TRANSCRIPT_SHA256, withdrawn)

    def test_the_withdrawal_is_recorded_rather_than_history_rewritten(self) -> None:
        claims = self.closure["withdrawn_claims"]
        self.assertTrue(claims)
        claim = claims[0]
        self.assertEqual(claim["declared_full_transcript_bytes"], WITHDRAWN_FULL_TRANSCRIPT_BYTES)
        self.assertEqual(
            claim["declared_full_transcript_sha256"], WITHDRAWN_FULL_TRANSCRIPT_SHA256
        )
        self.assertEqual(claim["bytes_actually_present"], 29)
        self.assertEqual(claim["withdrawn_by"], "M2-M64")
        self.assertTrue(claim["where_it_appeared"])
        self.assertTrue(claim["why_it_was_untrue"])
        # The prior report keeps its own bytes: a record of what an earlier
        # closure claimed is evidence, and this pass withdraws rather than edits.
        committed = subprocess.run(
            ["git", "show", f"{STARTING_COMMIT}:implementation/{PRIOR_CLOSURE_REPORT.name}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(PRIOR_CLOSURE_REPORT.read_bytes(), committed)

    def test_no_current_object_calls_a_summary_a_complete_transcript(self) -> None:
        for name, node in self.nodes():
            summary = node.get("exact_result")
            if not isinstance(summary, str) or not summary:
                continue
            with self.subTest(node=name):
                self.assertFalse(
                    node.get("transcript_available"),
                    f"{name} offers a result summary as an available transcript",
                )
                self.assertFalse(
                    node.get("complete_transcript_available"),
                    f"{name} describes a result summary as a complete transcript",
                )
                self.assertIn(
                    "complete_transcript_disposition",
                    node,
                    f"{name} states a result without saying what became of the full output",
                )

    def test_the_current_run_never_claims_the_exact_commit_was_qualified(self) -> None:
        run = self.validation["canonical_current_run"]["delegated_physical"]
        self.assertEqual(run["scope"], "PRECOMMIT_WORKTREE")
        self.assertFalse(run["qualifies_exact_commit"])
        self.assertIn("uncommitted worktree", run["revision_qualified"])
        self.assertEqual(
            self.closure["exact_commit_external_evidence"]["status"],
            "PENDING_UNTIL_THE_EXACT_COMMIT_RUN",
        )
        self.assertEqual(
            self.closure["closure_status"],
            "IMPLEMENTED_AND_PRECOMMIT_QUALIFIED_PENDING_EXACT_COMMIT_EXTERNAL_EVIDENCE_"
            "AND_INDEPENDENT_AUDIT",
        )

    def test_history_and_the_current_run_are_never_conflated(self) -> None:
        current = self.validation["canonical_current_run"]
        historical = current["historical_delegated_qualifications"]
        self.assertTrue(historical)
        results = []
        for record in historical:
            with self.subTest(record=record.get("run_id")):
                self.assertTrue(record["historical"])
                self.assertFalse(record["qualifies_this_revision"])
                results.append(record.get("exact_result"))
        self.assertIn(HISTORICAL_STARTING_COMMIT_RESULT, results)
        self.assertNotEqual(
            current["delegated_physical"]["exact_result"], HISTORICAL_STARTING_COMMIT_RESULT
        )
        prior = self.validation["prior_physical_qualification"]
        self.assertEqual(prior["qualified_commit"], STARTING_COMMIT)
        self.assertFalse(prior["qualifies_this_repair"])
        self.assertEqual(prior["transcript"], HISTORICAL_STARTING_COMMIT_RESULT)

    def test_nothing_current_claims_acceptance_installation_or_milestone_three(self) -> None:
        for name, document in self.documents.items():
            with self.subTest(document=name):
                self.assertFalse(document["independent_acceptance_claimed"])
                self.assertFalse(document["installed_path_qualification_claimed"])
                for boundary, crossed in document["boundary_audit"].items():
                    self.assertFalse(crossed, f"{name}:{boundary}")
        self.assertFalse(self.closure["milestone_3_permitted"])
        self.assertEqual(self.closure["milestone_3_status"], "NOT_PERMITTED_AND_NOT_STARTED")


class ExactCommitEvidenceContractTests(unittest.TestCase):
    """The external evidence contract is exact, and it is executable."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.closure = _load(CLOSURE_REPORT)
        cls.contract = cls.closure["exact_commit_external_evidence"]

    def setUp(self) -> None:
        self.commit = "a" * 40
        self.parent = STARTING_COMMIT
        self.root = Path(tempfile.mkdtemp(prefix="m2-exact-commit-"))
        self.addCleanup(self._remove_root)
        self.transcript = self.root / self.contract["transcript_filename_template"].replace(
            "<commit>", self.commit
        )
        self.receipt = self.root / self.contract["receipt_filename_template"].replace(
            "<commit>", self.commit
        )

    def _remove_root(self) -> None:
        for path in sorted(self.root.glob("*")):
            path.unlink()
        self.root.rmdir()

    def write(self, *, body: str | None = None, **overrides):
        raw = (body if body is not None else "test ... ok\n" * 40 + "\nOK\n").encode("utf-8")
        self.transcript.write_bytes(raw)
        record = {
            "repository_path": str(REPOSITORY_ROOT),
            "branch": BRANCH,
            "commit": self.commit,
            "parent": self.parent,
            "bounded_range_count": 1,
            "worktree_clean": True,
            "command": self.contract["command"],
            "mode": "exact-commit-full",
            "modules": list(self.contract["required_modules"]),
            "environment": {"ADMISSIBLE_REQUIRE_DELEGATED_CGROUP": "1"},
            "exit_code": 0,
            "transcript_bytes": len(raw),
            "transcript_sha256": hashlib.sha256(raw).hexdigest(),
            "ran_line": "Ran 900 tests in 400.000s",
            "final_status": "OK",
            "skipped": 0,
            "failures": 0,
            "errors": 0,
            "started_at": "2026-08-06T00:00:00Z",
            "ended_at": "2026-08-06T00:07:00Z",
        }
        record.update(overrides)
        self.receipt.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        return record

    def refusals(self, **kwargs) -> list[str]:
        return _exact_commit_refusals(
            self.contract,
            transcript=kwargs.get("transcript", self.transcript),
            receipt=kwargs.get("receipt", self.receipt),
            commit=kwargs.get("commit", self.commit),
            parent=kwargs.get("parent", self.parent),
        )

    def test_the_contract_names_the_command_the_files_and_the_fields(self) -> None:
        self.assertEqual(
            self.contract["command"],
            "sudo -n /usr/local/sbin/admissible-m2-final-closure-qualify exact-commit-full",
        )
        self.assertEqual(
            self.contract["transcript_filename_template"], EXACT_COMMIT_TRANSCRIPT_TEMPLATE
        )
        self.assertEqual(
            self.contract["receipt_filename_template"], EXACT_COMMIT_RECEIPT_TEMPLATE
        )
        self.assertEqual(
            tuple(self.contract["required_receipt_fields"]), REQUIRED_RECEIPT_FIELDS
        )
        self.assertEqual(tuple(self.contract["required_modules"]), QUALIFICATION_MODULES)
        self.assertTrue(self.contract["produced_outside_the_repository"])
        self.assertEqual(self.contract["repository_mutation_after_the_run"], "FORBIDDEN")
        self.assertTrue(self.contract["why_it_cannot_live_in_this_commit"])

    def test_coherent_external_evidence_verifies(self) -> None:
        self.write()
        self.assertEqual(self.refusals(), [])

    def test_absent_evidence_is_refused(self) -> None:
        self.assertEqual(
            sorted(self.refusals()), ["EVIDENCE_ABSENT:receipt", "EVIDENCE_ABSENT:transcript"]
        )
        self.write()
        self.transcript.unlink()
        self.assertIn("EVIDENCE_ABSENT:transcript", self.refusals())

    def test_empty_evidence_is_refused(self) -> None:
        self.write(body="")
        self.assertIn("EVIDENCE_EMPTY:transcript", self.refusals())

    def test_evidence_tied_to_another_commit_is_refused(self) -> None:
        self.write()
        self.assertIn("RECEIPT_COMMIT_MISMATCH", self.refusals(commit="b" * 40))
        self.write(parent="c" * 40)
        self.assertIn("RECEIPT_PARENT_MISMATCH", self.refusals())

    def test_inconsistent_evidence_is_refused(self) -> None:
        self.write(transcript_sha256="0" * 64)
        self.assertIn("TRANSCRIPT_HASH_MISMATCH", self.refusals())
        self.write(transcript_bytes=1)
        self.assertIn("TRANSCRIPT_BYTE_COUNT_MISMATCH", self.refusals())

    def test_an_incomplete_or_unclean_run_is_refused(self) -> None:
        self.write(skipped=1)
        self.assertIn("RECEIPT_NOT_A_CLEAN_RUN", self.refusals())
        self.write(final_status="FAILED (failures=1)")
        self.assertIn("RECEIPT_NOT_A_CLEAN_RUN", self.refusals())
        self.write(modules=list(QUALIFICATION_MODULES[:-1]))
        self.assertIn("RECEIPT_MODULES_INCOMPLETE", self.refusals())
        self.write(bounded_range_count=2)
        self.assertIn("RECEIPT_BOUNDED_RANGE_NOT_ONE", self.refusals())
        self.write(worktree_clean=False)
        self.assertIn("RECEIPT_WORKTREE_NOT_CLEAN", self.refusals())

    def test_a_receipt_missing_a_required_field_is_refused(self) -> None:
        for field in REQUIRED_RECEIPT_FIELDS:
            with self.subTest(field=field):
                record = self.write()
                record.pop(field)
                self.receipt.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
                self.assertIn(f"RECEIPT_FIELD_MISSING:{field}", self.refusals())

    def test_the_bundle_rules_are_declared_where_a_third_party_reads_them(self) -> None:
        rules = self.contract["audit_bundle_rules"]
        self.assertEqual(
            sorted(rules["receives"]), ["receipt_path", "transcript_path"]
        )
        self.assertTrue(rules["verifies"])
        self.assertEqual(
            sorted(rules["includes_as_first_class_manifest_members"]),
            ["receipt", "transcript"],
        )
        for refusal in (
            "either file is absent",
            "either file is empty",
            "the transcript hash disagrees with the receipt",
            "the receipt names another commit",
        ):
            self.assertIn(refusal, rules["refuses_when"], refusal)


class ClosureArtifactCoherenceTests(unittest.TestCase):
    """The current artifacts describe this code, this run, and nothing stronger."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.closure = _load(CLOSURE_REPORT)
        cls.validation = _load(VALIDATION_REPORT)
        cls.matrix = _load(REQUIREMENT_MATRIX)
        cls.current_run = cls.validation["canonical_current_run"]
        cls.delegated_run = cls.current_run["delegated_physical"]

    def test_the_report_names_only_this_pass_and_its_starting_point(self) -> None:
        self.assertEqual(self.closure["branch"], BRANCH)
        self.assertEqual(self.closure["starting_commit"], STARTING_COMMIT)
        self.assertEqual(self.closure["starting_commit_parent"], STARTING_COMMIT_PARENT)
        self.assertEqual(self.closure["sole_parent_required"], STARTING_COMMIT)
        self.assertEqual(sorted(self.closure["findings"]), ["M2-B63", "M2-M64"])
        for finding in self.closure["finding_details"]:
            with self.subTest(finding=finding["finding"]):
                self.assertEqual(finding["status"], "IMPLEMENTED")
                self.assertTrue(finding["reproduction"])
                self.assertTrue(finding["closure"])
                self.assertTrue(finding["evidence"])
                self.assertTrue(finding["refusal_condition"])
        self.assertNotIn("ending_commit", self.closure)

    def test_the_independent_refusal_is_recorded_verbatim(self) -> None:
        for document, name in ((self.closure, "closure"), (self.validation, "validation")):
            with self.subTest(document=name):
                self.assertEqual(document["independent_audit_sha256"], INDEPENDENT_AUDIT_SHA256)
                self.assertEqual(
                    tuple(document["independent_audit_verdicts"]), INDEPENDENT_AUDIT_VERDICTS
                )

    def test_the_two_current_reports_carry_one_canonical_run(self) -> None:
        self.assertTrue(self.validation["is_current_validation_report"])
        self.assertEqual(self.validation["current_closure_key"], CLOSURE_KEY)
        self.assertEqual(self.closure["canonical_current_run"], self.current_run)
        self.assertEqual(self.validation["branch"], self.closure["branch"])
        self.assertEqual(self.validation["starting_commit"], self.closure["starting_commit"])
        self.assertEqual(self.validation["terminal_verdict"], self.closure["terminal_verdict"])
        self.assertEqual(
            self.validation["final_repair_report"],
            "implementation/M2_FINAL_ALIAS_PROOF_TRANSCRIPT_CLOSURE_REPORT.json",
        )
        self.assertEqual(
            self.validation[CLOSURE_KEY]["delegated_run"],
            self.closure["delegated_physical_qualification"]["run"],
        )
        self.assertEqual(self.validation[CLOSURE_KEY]["delegated_run"], self.delegated_run)

    def test_the_prior_closure_is_recorded_as_superseded_and_frozen(self) -> None:
        superseded = "implementation/M2_ALIAS_CAPACITY_ARTIFACT_TCB_CLOSURE_REPORT.json"
        self.assertIn(superseded, self.validation["superseded_closure_reports"])
        link = self.validation["supersedes_prior_current_report"]
        self.assertEqual(link["commit"], STARTING_COMMIT)
        self.assertEqual(link["path"], "implementation/M2_VALIDATION_REPORT.json")
        raw = subprocess.run(
            ["git", "show", f"{link['commit']}:{link['path']}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(hashlib.sha256(raw).hexdigest(), link["sha256"])

    def test_the_historical_artifacts_are_preserved_byte_for_byte(self) -> None:
        for name in self.closure["preserved_historical_artifacts"]:
            with self.subTest(artifact=name):
                committed = subprocess.run(
                    ["git", "show", f"{STARTING_COMMIT}:implementation/{name}"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual((IMPLEMENTATION / name).read_bytes(), committed)

    def test_the_declared_qualification_modules_are_the_ten_on_disk(self) -> None:
        run = self.delegated_run
        self.assertEqual(tuple(run["expected_modules"]), QUALIFICATION_MODULES)
        self.assertEqual(len(run["expected_modules"]), 10)
        self.assertEqual(run["expected_skips"], 0)
        for module in run["expected_modules"]:
            with self.subTest(module=module):
                path = REPOSITORY_ROOT / f"{module.replace('.', '/')}.py"
                self.assertTrue(path.is_file(), f"{module} is declared but is not on disk")

    def test_the_expected_delegated_total_matches_the_modules_as_they_stand(self) -> None:
        run = self.delegated_run
        expected = sum(
            unittest.defaultTestLoader.loadTestsFromName(module).countTestCases()
            for module in run["expected_modules"]
        )
        self.assertEqual(run["expected_total"], expected)
        self.assertEqual(run["executed"], expected)
        self.assertEqual(sum(run["module_totals"].values()), expected)
        for module, total in run["module_totals"].items():
            with self.subTest(module=module):
                self.assertEqual(
                    unittest.defaultTestLoader.loadTestsFromName(module).countTestCases(),
                    total,
                )

    def test_the_live_discovery_counts_match_the_files_on_disk(self) -> None:
        counts = self.validation["test_counts"]["per_module"]
        for name in counts:
            with self.subTest(module=name):
                self.assertTrue(
                    (REPOSITORY_ROOT / "tests" / f"{name}.py").is_file(),
                    f"{name} is counted but is not a file on disk",
                )
        this_module = THIS_MODULE.split(".", 1)[1]
        live = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__]).countTestCases()
        self.assertEqual(counts[this_module], live, "this module's declared count is stale")
        self.assertEqual(self.closure["module_tests_total"], live)
        self.assertEqual(
            self.closure["deterministic_tests"] + self.closure["delegated_tests"], live
        )
        m1 = sum(value for name, value in counts.items() if "_m1" in name)
        m2 = sum(value for name, value in counts.items() if "_m2" in name)
        self.assertEqual(m1, self.validation["test_counts"]["m1_tests"])
        self.assertEqual(m2, self.validation["test_counts"]["m2_tests"])
        self.assertEqual(m1 + m2, self.validation["test_counts"]["discovered_total"])
        self.assertEqual(
            self.validation["test_counts"]["total"],
            self.validation["test_counts"]["discovered_total"],
        )
        self.assertEqual(self.current_run["m1_total"], self.validation["test_counts"]["m1_tests"])
        self.assertEqual(
            self.current_run["m2_discovered_total"], self.validation["test_counts"]["m2_tests"]
        )

    def test_the_matrix_records_this_closure_without_claiming_more(self) -> None:
        note = self.matrix[f"{CLOSURE_KEY}_note"]
        for finding in ("M2-B63", "M2-M64"):
            self.assertIn(finding, note)
        self.assertIn("M2_FINAL_ALIAS_PROOF_TRANSCRIPT_CLOSURE_REPORT.json", note)
        self.assertEqual(self.matrix["requirement_count"], len(self.matrix["requirements"]))
        records = {row["requirement_id"]: row for row in self.matrix["requirements"]}
        for requirement_id in ("EXEC-06", "EVID-08"):
            with self.subTest(requirement=requirement_id):
                entry = records[requirement_id][CLOSURE_KEY]
                self.assertEqual(
                    entry["closed_by"],
                    "implementation/M2_FINAL_ALIAS_PROOF_TRANSCRIPT_CLOSURE_REPORT.json",
                )
                self.assertEqual(entry["findings"], ["M2-B63", "M2-M64"])
                self.assertTrue(entry["implemented"])
                self.assertTrue(entry["unit_verified"])
                self.assertFalse(entry["independently_accepted"])
                self.assertFalse(entry["installed_path_qualified"])
                self.assertFalse(entry["exact_commit_evidence_present"])
        self.assertEqual(records["EXEC-06"]["current_status"], "VERIFIED_INTEGRATION")
        self.assertEqual(records["EVID-08"]["current_status"], "IMPLEMENTED")

    def test_the_accepted_prior_closures_are_not_reopened(self) -> None:
        preserved = self.closure["preserved_closures"]
        self.assertTrue(preserved["b26_and_b27_closed"])
        self.assertTrue(preserved["b56_to_b58_preserved"])
        self.assertTrue(preserved["b59_to_m62_preserved"])
        prior = _load(PRIOR_CLOSURE_REPORT)
        self.assertEqual(
            sorted(prior["findings"]), ["M2-B59", "M2-B60", "M2-M61", "M2-M62"]
        )
        self.assertIn(PRIOR_CLOSURE_REPORT.name, self.closure["preserved_historical_artifacts"])

    def test_the_module_inventory_matches_the_package_on_disk(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        modules = sorted(path.name for path in package.glob("*.py"))
        self.assertEqual(self.closure["module_inventory"], modules)
        self.assertEqual(self.closure["module_count"], len(modules))

    def test_no_forbidden_scope_was_entered(self) -> None:
        package = REPOSITORY_ROOT / "admissible" / "paired_runner"
        present = {path.name for path in package.glob("*.py")}
        for name in (
            "transport.py",
            "direct_mode.py",
            "governed_mode.py",
            "policy.py",
            "authority.py",
            "evaluator.py",
            "archive.py",
            "benchmark.py",
        ):
            self.assertNotIn(name, present)
        for module in ("resource_limits.py", "private_workspace.py", "process_ownership.py"):
            text = (package / module).read_text(encoding="utf-8")
            for token in ("requests", "urllib", "http", "socket"):
                if module == "private_workspace.py" and token == "socket":
                    continue
                with self.subTest(module=module, forbidden=token):
                    self.assertNotIn(f"import {token}", text)
                    self.assertNotIn(f"from {token}", text)


# --- delegated physical qualification -----------------------------------------


class DelegatedFinalAliasProofTranscriptTests(unittest.TestCase):
    """Physical qualification of M2-B63 on real kernel state."""

    @classmethod
    def setUpClass(cls) -> None:
        if REQUIRE_DELEGATED and not DELEGATION.available:
            raise AssertionError(
                "ADMISSIBLE_REQUIRE_DELEGATED_CGROUP=1 but no delegated cgroup v2 "
                f"topology is available: {DELEGATION.detail}"
            )

    def setUp(self) -> None:
        guard_process_wide_cgroup_caches(self)
        self.before = _ProcessGuard.install(self)
        self.addCleanup(self._teardown_every_obligation)

    def _teardown_every_obligation(self) -> None:
        for _attempt in range(4):
            retained = list(pw.incomplete_cleanups()) + list(rl.unregistered_cleanups())
            if not retained:
                break
            try:
                pw.drain_incomplete_cleanups(
                    deadline=Deadline.after_ms(RETRY_BUDGET_MS, "delegated_teardown")
                )
            except Exception:  # pragma: no cover - the teardown never masks a failure
                break

    def _require_live_delegation(self) -> None:
        delegation = ps.cgroup_delegation()
        self.assertTrue(
            delegation.available,
            "the process-wide delegation cache is not usable before this effect: "
            f"code={delegation.code!r} detail={delegation.detail!r}",
        )

    def _real_cgroup(self, label: str) -> rl.EffectCgroup:
        delegation = ps.cgroup_delegation()
        cgroup = rl.EffectCgroup(delegation, rl.ResourceBounds.for_timeout(1_000), label)
        self.assertTrue(cgroup.create(), cgroup.create_error)
        return cgroup

    def _twin(self, cgroup: rl.EffectCgroup, label: str) -> rl.EffectCgroup:
        """A second handle naming the exact same owned cgroup."""

        twin = rl.EffectCgroup(
            ps.cgroup_delegation(), rl.ResourceBounds.for_timeout(1_000), label
        )
        twin._parent_fd = os.dup(cgroup._parent_fd)
        twin._dir_fd = os.dup(cgroup._dir_fd)
        twin._parent_identity = cgroup._parent_identity
        twin._owned_identity = cgroup._owned_identity
        twin._leaf = cgroup._leaf
        twin._path = cgroup._path
        twin._owned_path = cgroup._owned_path
        self.assertEqual(cgroup.owned_identity, twin.owned_identity)
        return twin

    def test_the_no_false_green_variable_forbids_skipping(self) -> None:
        if REQUIRE_DELEGATED:
            self.assertTrue(DELEGATION.available, DELEGATION.detail)
            self.assertTrue(CAPSULE_READY.available, CAPSULE_READY.probe_detail)
        else:
            self.skipTest("ADMISSIBLE_REQUIRE_DELEGATED_CGROUP is not set")

    def test_the_branch_and_revision_are_the_ones_under_qualification(self) -> None:
        branch = _git("branch", "--show-current")
        self.assertTrue(
            branch.startswith("paired-runner/m2-"),
            f"this module is qualified only on a bounded Milestone 2 closure branch: {branch!r}",
        )
        self.assertEqual(_git("merge-base", STARTING_COMMIT, "HEAD"), STARTING_COMMIT)
        self.assertEqual(_git("rev-parse", f"{STARTING_COMMIT}^"), STARTING_COMMIT_PARENT)
        ahead = int(_git("rev-list", "--count", f"{STARTING_COMMIT}..HEAD"))
        self.assertLessEqual(
            ahead,
            1 if branch == BRANCH else 2,
            "more than one commit stands on top of this closure's starting point",
        )

    @delegated
    def test_a_real_prior_publication_names_its_actual_proof_source(self) -> None:
        """M2-B63 physically, on a real delegated cgroup.  The wrapper names this."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        self._require_live_delegation()
        parent = Path(DELEGATION.delegated_path)
        # Attempts and successful destructions are counted apart: the kernel
        # refusing an ENOTEMPTY rmdir is an attempt that destroyed nothing, and
        # "the resource was destroyed once" is a statement about the second list.
        attempts: list[str] = []
        destroyed: list[str] = []
        real_rmdir = rl._rmdir_owned_child

        def recording(parent_fd, leaf):
            attempts.append(leaf)
            outcome = real_rmdir(parent_fd, leaf)
            if outcome[0]:
                destroyed.append(leaf)
            return outcome

        cgroup = self._real_cgroup(f"b63-real-{os.getpid()}")
        path = Path(cgroup.owned_path)
        self.assertTrue(path.is_dir())
        # A real nested cgroup: the kernel itself refuses the owned rmdir with
        # ENOTEMPTY, so the first drain is genuinely unresolved.  No primitive is
        # stubbed and no failure is simulated.
        nested = path / "nested"
        nested.mkdir(mode=0o700)
        self.addCleanup(lambda: nested.is_dir() and nested.rmdir())
        self.assertFalse(cgroup.close(), "a cgroup with a live child was removed")
        self.assertIsNotNone(cgroup.cleanup_registry_id, "the obligation was not retained")

        # Every twin duplicates the descriptors while they are still open; each
        # is retained later, and the process-wide obligation sequence follows the
        # order they are retained in, not the order they were built.
        claimed = self._twin(cgroup, "b63-real-claimed")
        source = self._twin(cgroup, "b63-real-source")
        late = self._twin(cgroup, "b63-real-late")
        # A second registry entry over the exact same cgroup, owned by another
        # drain for the whole test.  It is retained while the resource is still
        # outstanding, it never settles anything, and it becomes the canonical
        # obligation of the group only once the obligations before it are gone.
        entry_id = pw._CLEANUP_REGISTRY.record(claimed, claimed.cleanup_evidence())
        self.assertIsNotNone(entry_id, "the claimed canonical was not retained")
        entry = pw._CLEANUP_REGISTRY.entry(entry_id)
        entry.claimed_by = threading.get_ident() + 1
        self.addCleanup(setattr, entry, "claimed_by", None)
        rl._retain_unregistered(source)
        self.addCleanup(rl._release_unregistered, source)

        # Drain one: the canonical obligation is the registered entry and it
        # cannot settle, so nothing is discharged and nothing is published.
        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            rows = pw.drain_incomplete_cleanups(
                deadline=Deadline.after_ms(2_000, "b63-first")
            )
        aliases = [row for row in rows if row["alias_of"] is not None]
        self.assertEqual(len(aliases), 1, rows)
        self.assertEqual(aliases[0]["state"], pw.DRAIN_STATE_RETAINED_PENDING_CANONICAL)
        self.assertEqual(
            aliases[0]["discharge_proof_origin"], pw.DISCHARGE_PROOF_ORIGIN_NONE
        )
        self.assertEqual(destroyed, [], "a refused removal destroyed the cgroup anyway")
        self.assertTrue(path.is_dir(), "the retained cgroup was removed anyway")

        # Drain two, with the obstruction gone: the registered entry settles the
        # real cgroup exactly once and publishes the terminal result.
        nested.rmdir()
        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            rows = pw.drain_incomplete_cleanups(
                deadline=Deadline.after_ms(RETRY_BUDGET_MS, "b63-settle")
            )
        self.assertEqual(len(destroyed), 1, "the real cgroup was destroyed more than once")
        self.assertFalse(path.exists(), "the owned cgroup was never removed")
        attempts_before_attribution = len(attempts)
        identity = cgroup.owned_identity
        published = pw._published_canonical_result(identity)
        self.assertIsNotNone(published, "the terminal result was not published")
        proving_label = published.label
        proving_generation = published.generation
        # The obligation that proved it drops out; the twin that did not is the
        # only carrier of that label left, and it is released deliberately.
        rl._release_unregistered(source)

        # A later drain over the exact same resource whose own selected canonical
        # is claimed by another drain: the alias must name the result that proved
        # the discharge, not the canonical this drain happened to select.
        self.assertIs(pw._CLEANUP_REGISTRY.entry(entry_id), entry, "the claim was lost")
        rl._retain_unregistered(late)
        self.addCleanup(rl._release_unregistered, late)

        with mock.patch.object(rl, "_rmdir_owned_child", recording):
            rows = pw.drain_incomplete_cleanups(
                deadline=Deadline.after_ms(RETRY_BUDGET_MS, "b63-attribute")
            )
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["resource_identity"], identity)
        self.assertEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_PUBLISHED_RESULT)
        self.assertEqual(
            row["discharge_proof_origin"],
            pw.DISCHARGE_PROOF_ORIGIN_OTHER_DRAIN_PUBLISHED_RESULT,
        )
        self.assertEqual(row["discharge_proof_source_label"], proving_label)
        self.assertEqual(row["discharge_proof_generation"], proving_generation)
        self.assertNotEqual(
            row["discharge_proof_source_label"],
            row["group_canonical_label"],
            "a real alias credited its discharge to the canonical selected here",
        )
        self.assertNotEqual(row["state"], pw.DRAIN_STATE_DISCHARGED_BY_CANONICAL)
        self.assertEqual(row["granted_ms"], 0, "a real alias spent a second grant")
        self.assertEqual(
            len(attempts),
            attempts_before_attribution,
            "a second destructive primitive executed for a resource already proved gone",
        )
        self.assertEqual(len(destroyed), 1, "the real cgroup was destroyed more than once")

        # Converge: nothing owned, retained, held or owed is left behind.
        entry.claimed_by = None
        for _attempt in range(4):
            if not (list(pw.incomplete_cleanups()) or list(rl.unregistered_cleanups())):
                break
            pw.drain_incomplete_cleanups(
                deadline=Deadline.after_ms(RETRY_BUDGET_MS, "b63-converge")
            )
        self.assertEqual(len(destroyed), 1, "convergence destroyed a cgroup a second time")
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(rl.unregistered_cleanups(), (), "an unregistered obligation leaked")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)
        self.assertFalse(CHILD_SUBREAPER.active, "subreaper ownership leaked")
        self.assertIsNone(po.process_restoration_debt(), "restoration debt leaked")

    @delegated
    def test_no_residual_state_survives_this_module(self) -> None:
        """Nothing owned, retained, held or owed is left behind."""

        self.assertTrue(DELEGATION.available, DELEGATION.detail)
        pw.drain_incomplete_cleanups(deadline=Deadline.after_ms(RETRY_BUDGET_MS, "residual"))
        parent = Path(DELEGATION.delegated_path)
        self.assertEqual(_effect_cgroups(parent), [], "a per-effect cgroup leaked")
        self.assertEqual(sorted(parent.glob(f"{rl.PROBE_PREFIX}*")), [], "a probe cgroup leaked")
        self.assertEqual(rl.unregistered_cleanups(), (), "an unregistered obligation leaked")
        evidence = pw.cleanup_registry_evidence()
        self.assertEqual(evidence["retained"], 0, evidence)
        self.assertEqual(evidence["reserved"], 0, evidence)
        self.assertEqual(pw.unsettled_failed_starts(), (), "a failed start leaked")
        self.assertFalse(CHILD_SUBREAPER.active, "subreaper ownership leaked")
        self.assertIsNone(po.process_restoration_debt(), "restoration debt leaked")
        self.assertEqual(
            po.get_child_subreaper()[0], self.before, "the kernel flag was left changed"
        )
        self.assertEqual(
            rl.cgroup_mutation_domains_evidence()["held_by_this_thread"],
            [],
            "a mutation boundary was left held",
        )


if __name__ == "__main__":
    unittest.main()
