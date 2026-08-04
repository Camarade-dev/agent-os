"""Functional and negative tests for the Milestone 2 shared effect substrate.

Every physical effect in this file happens inside a disposable temporary
workspace created by the test process and removed afterwards.  No test touches
the repository worktree, a production root, a provider, a model, a policy
engine, an owner authority, a broker, a mint, a witness, or a V14-V18 identity.
"""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
    initialise_git_repository,
)
from admissible.paired_runner.durable_store import (  # noqa: E402
    CorruptDurableObject,
    DurableObjectStore,
    PublicationConflict,
)
from admissible.paired_runner.effect_ledger import RunEffectLedger  # noqa: E402
from admissible.paired_runner.sandbox import CAPSULE_ENVIRONMENT  # noqa: E402
from admissible.paired_runner.effects import (  # noqa: E402
    OBJECT_KIND_LIFECYCLE_STARTED,
    OBJECT_KIND_PROPOSAL,
    OBJECT_KIND_RESERVATION,
    PRE_EFFECT_OBJECT_KINDS,
    SANITIZED_ENVIRONMENT_BASE,
    SharedEffectSubstrate,
    WorkspaceBinding,
    observe_git,
)
from admissible.paired_runner.process_supervision import CancellationToken  # noqa: E402
from admissible.paired_runner.tool_schemas import (  # noqa: E402
    ListFilesRequest,
    ListFilesResult,
    ReadFileRequest,
    RunCommandRequest,
    WriteFileRequest,
)


class _Harness:
    """One disposable workspace plus one bound substrate for one condition."""

    def __init__(self, condition_id: str = "DIRECT", *, run_id: str | None = None, cancellation=None) -> None:
        self.condition_id = condition_id
        self.specification = build_specification(condition_id, run_id=run_id or f"run-{condition_id.lower()}")
        self.grammar = self.specification.tool_grammar.grammar_fingerprint
        self.disposable = DisposableWorkspace()
        self.workspace = self.disposable.workspace
        self.boundary_observations: list[tuple[str, ...]] = []
        self.binding = None
        self.substrate = None
        self.cancellation = cancellation
        self._counter = 0

    def bind(self) -> "_Harness":
        self.binding = WorkspaceBinding.bind(
            self.workspace, self.specification, evidence_root=self.disposable.store_root
        )
        self.store = DurableObjectStore(self.disposable.store_root)

        def boundary_hook() -> None:
            self.boundary_observations.append(
                tuple(
                    sorted(
                        kind
                        for kind in PRE_EFFECT_OBJECT_KINDS
                        if self.store.inspect(kind, self._current_proposal_id).durable
                    )
                )
            )

        self.substrate = SharedEffectSubstrate(
            binding=self.binding,
            store=self.store,
            ledger=RunEffectLedger(self.specification.run_identity.run_id),
            effect_boundary_hook=boundary_hook,
            cancellation=self.cancellation,
        )
        return self

    def run(self, request, *, governed_decision: str = "ALLOW"):
        self._counter += 1
        proposal_id = f"proposal-{self._counter}"
        self._current_proposal_id = proposal_id
        proposal = build_proposal(self.specification, request, proposal_id=proposal_id)
        decision = decision_for(proposal, governed_decision=governed_decision)
        return self.substrate.execute(
            specification=self.specification,
            proposal=proposal,
            decision=decision,
            reservation_id=f"reservation-{self._counter}",
            receipt_id=f"receipt-{self._counter}",
        )

    def close(self) -> None:
        if self.binding is not None:
            self.binding.close()
        self.disposable.close()


def _flood_script(stream: str, chunk: str, repeats: int) -> str:
    return (
        "import sys\n"
        f"target = sys.{stream}\n"
        f"for _ in range({repeats}):\n"
        f"    target.write({chunk!r})\n"
        "target.flush()\n"
    )


class SharedSubstrateFunctionalTests(unittest.TestCase):
    """Positive coverage for the four exact M1 tool contracts."""

    def setUp(self) -> None:
        self.harness = _Harness().bind()
        self.addCleanup(self.harness.close)

    def test_list_files_returns_sorted_unique_relative_posix_paths(self) -> None:
        (self.harness.workspace / "b.txt").write_text("b", encoding="utf-8")
        (self.harness.workspace / "a.txt").write_text("a", encoding="utf-8")
        (self.harness.workspace / "nested").mkdir()
        (self.harness.workspace / "nested" / "c.txt").write_text("c", encoding="utf-8")

        shallow = self.harness.run(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", recursive=False)
        )
        self.assertEqual(shallow.receipt.status, "COMPLETED")
        self.assertEqual(shallow.tool_result.entries, ("a.txt", "b.txt", "nested"))
        self.assertFalse(shallow.tool_result.truncated)

        deep = self.harness.run(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", recursive=True)
        )
        self.assertEqual(deep.tool_result.entries, ("a.txt", "b.txt", "nested", "nested/c.txt"))

    def test_list_files_truncates_exactly_at_the_request_entry_bound(self) -> None:
        for index in range(6):
            (self.harness.workspace / f"file-{index}.txt").write_text("x", encoding="utf-8")
        outcome = self.harness.run(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", max_entries=3)
        )
        self.assertTrue(outcome.tool_result.truncated)
        self.assertEqual(len(outcome.tool_result.entries), 3)
        outcome.tool_result.validate_for_request(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", max_entries=3)
        )

    def test_read_file_returns_exact_bounded_utf8_content(self) -> None:
        (self.harness.workspace / "text.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")
        outcome = self.harness.run(
            ReadFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="text.txt")
        )
        self.assertEqual(outcome.tool_result.content, "one\ntwo\nthree\n")
        self.assertEqual(outcome.tool_result.bytes_read, 14)
        self.assertFalse(outcome.tool_result.truncated)

    def test_read_file_honours_start_line_and_max_lines_with_explicit_truncation(self) -> None:
        (self.harness.workspace / "text.txt").write_text("1\n2\n3\n4\n5\n", encoding="utf-8")
        outcome = self.harness.run(
            ReadFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="text.txt", start_line=2, max_lines=2
            )
        )
        self.assertEqual(outcome.tool_result.content, "2\n3\n")
        self.assertTrue(outcome.tool_result.truncated)

    def test_write_file_creates_parents_only_when_requested(self) -> None:
        refused = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                path="missing/child.txt",
                content="x",
                create_parents=False,
            )
        )
        self.assertEqual(refused.receipt.status, "REFUSED")
        self.assertEqual(refused.tool_result.error_code, "parent_directory_absent")
        self.assertFalse((self.harness.workspace / "missing").exists())

        created = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                path="missing/child.txt",
                content="x",
                create_parents=True,
            )
        )
        self.assertEqual(created.receipt.status, "COMPLETED")
        self.assertTrue((self.harness.workspace / "missing" / "child.txt").is_file())

    def test_write_file_writes_the_exact_requested_bytes_and_overwrites_atomically(self) -> None:
        content = "exact é bytes\n"
        first = self.harness.run(
            WriteFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="w.txt", content=content)
        )
        target = self.harness.workspace / "w.txt"
        self.assertEqual(target.read_bytes(), content.encode("utf-8"))
        self.assertEqual(first.tool_result.bytes_written, len(content.encode("utf-8")))
        first.tool_result.validate_for_request(
            WriteFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="w.txt", content=content)
        )
        replacement = "replaced\n"
        self.harness.run(
            WriteFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="w.txt", content=replacement)
        )
        self.assertEqual(target.read_bytes(), replacement.encode("utf-8"))
        self.assertEqual(
            [entry for entry in os.listdir(self.harness.workspace) if entry.startswith(".tmp-write-")], []
        )

    def test_run_command_records_stdout_stderr_and_a_non_zero_exit_code(self) -> None:
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", "import sys;sys.stdout.write('o');sys.stderr.write('e');sys.exit(7)"],
                timeout_ms=30_000,
            )
        )
        # Tool execution success and command exit status are separate facts.
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        self.assertEqual(outcome.tool_result.outcome, "OK")
        self.assertEqual(outcome.tool_result.exit_code, 7)
        self.assertEqual(outcome.receipt.process_exit_code, 7)
        self.assertIsNone(outcome.receipt.task_acceptance)

    def test_run_command_environment_carries_no_inherited_variable(self) -> None:
        os.environ["ADMISSIBLE_M2_SECRET_PROBE"] = "must-not-be-inherited"
        self.addCleanup(os.environ.pop, "ADMISSIBLE_M2_SECRET_PROBE", None)
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", "import os,sys;sys.stdout.write(','.join(sorted(os.environ)))"],
                timeout_ms=30_000,
            )
        )
        names = set(outcome.tool_result.stdout.split(","))
        self.assertNotIn("ADMISSIBLE_M2_SECRET_PROBE", names)
        # The capsule builds its environment from nothing (--clearenv), so the
        # exact capsule environment -- not a sanitised copy of the host's -- is
        # what a command may observe.
        self.assertLessEqual(names, set(CAPSULE_ENVIRONMENT))


class WorkspaceConfinementTests(unittest.TestCase):
    """Fail-closed confinement, including every symlink escape class."""

    def setUp(self) -> None:
        self.harness = _Harness().bind()
        self.addCleanup(self.harness.close)
        self.outside = Path(self.harness.disposable.root) / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("outside-secret\n", encoding="utf-8")

    def test_absolute_and_traversing_paths_are_refused_by_the_typed_request(self) -> None:
        for path in ("/etc/passwd", "../escape.txt", "a/../../b", "a\\b", "a\x00b"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    ReadFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=path)

    def test_final_symlink_escape_cannot_be_read(self) -> None:
        os.symlink(self.outside / "secret.txt", self.harness.workspace / "link.txt")
        outcome = self.harness.run(
            ReadFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="link.txt")
        )
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "final_path_is_symlink")
        self.assertEqual(outcome.tool_result.content, "")

    def test_parent_symlink_escape_cannot_be_read(self) -> None:
        os.symlink(self.outside, self.harness.workspace / "escape")
        outcome = self.harness.run(
            ReadFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="escape/secret.txt")
        )
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "path_component_is_symlink")

    def test_recursive_symlink_escape_is_listed_but_never_traversed(self) -> None:
        os.symlink(self.outside, self.harness.workspace / "escape")
        outcome = self.harness.run(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", recursive=True)
        )
        self.assertEqual(outcome.tool_result.entries, ("escape",))
        self.assertNotIn("escape/secret.txt", outcome.tool_result.entries)

    def test_write_file_refuses_a_final_symlink_and_never_writes_through_it(self) -> None:
        target = self.outside / "secret.txt"
        os.symlink(target, self.harness.workspace / "link.txt")
        outcome = self.harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=self.harness.grammar, path="link.txt", content="overwritten"
            )
        )
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertEqual(outcome.tool_result.error_code, "final_path_is_symlink")
        self.assertEqual(target.read_text(encoding="utf-8"), "outside-secret\n")

    def test_run_command_cwd_must_remain_physically_under_the_root(self) -> None:
        os.symlink(self.outside, self.harness.workspace / "escape")
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", "pass"],
                cwd="escape",
                timeout_ms=10_000,
            )
        )
        self.assertEqual(outcome.receipt.status, "REFUSED")
        self.assertFalse(outcome.tool_result.process_started)

    def test_outside_root_files_are_not_listable(self) -> None:
        outcome = self.harness.run(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", recursive=True)
        )
        self.assertEqual(outcome.tool_result.entries, ())

    def test_binding_refuses_a_symlinked_or_non_canonical_root(self) -> None:
        link = Path(self.harness.disposable.root) / "workspace-link"
        os.symlink(self.harness.workspace, link)
        store_root = self.harness.disposable.store_root
        with self.assertRaises(ValueError):
            WorkspaceBinding.bind(link, self.harness.specification, evidence_root=store_root)
        with self.assertRaises(ValueError):
            WorkspaceBinding.bind("relative/path", self.harness.specification, evidence_root=store_root)

    def test_binding_refuses_a_specification_it_was_not_bound_to(self) -> None:
        other = build_specification("GOVERNED", run_id="run-other")
        with self.assertRaises(ValueError):
            self.harness.binding.validate_for_specification(other)

    def test_non_utf8_file_content_is_refused_rather_than_replaced(self) -> None:
        (self.harness.workspace / "binary.bin").write_bytes(b"\xff\xfe\x00\x01")
        outcome = self.harness.run(
            ReadFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="binary.bin")
        )
        self.assertEqual(outcome.receipt.status, "FAILED")
        self.assertEqual(outcome.tool_result.error_code, "non_utf8_file")
        self.assertEqual(outcome.tool_result.content, "")


class ProcessSupervisionTests(unittest.TestCase):
    """Timeout, cancellation, descendant cleanup, and bounded output."""

    def setUp(self) -> None:
        self.harness = _Harness().bind()
        self.addCleanup(self.harness.close)

    def test_command_start_failure_is_typed_and_never_claims_a_process(self) -> None:
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=["/nonexistent/admissible-m2-absent-binary"],
                timeout_ms=10_000,
            )
        )
        self.assertEqual(outcome.receipt.status, "FAILED")
        self.assertFalse(outcome.tool_result.process_started)
        self.assertEqual(outcome.tool_result.error_code, "executor_start_failure")
        self.assertIsNone(outcome.tool_result.exit_code)

    def test_timeout_terminates_the_process_group_and_records_TIMED_OUT(self) -> None:
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", "import time;time.sleep(30)"],
                timeout_ms=800,
            )
        )
        self.assertEqual(outcome.receipt.status, "TIMED_OUT")
        self.assertTrue(outcome.receipt.reconciliation_required)
        self.assertFalse(outcome.receipt.effect_completed)
        entry = outcome.ledger_entry
        self.assertIsNotNone(entry.process_observation_fingerprint)

    def test_cancellation_terminates_the_process_group_and_records_CANCELLED(self) -> None:
        token = CancellationToken()
        harness = _Harness(run_id="run-cancel", cancellation=token).bind()
        self.addCleanup(harness.close)
        timer = threading.Timer(0.4, token.cancel)
        timer.start()
        self.addCleanup(timer.cancel)
        outcome = harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=harness.grammar,
                argv=[PYTHON, "-c", "import time;time.sleep(30)"],
                timeout_ms=30_000,
            )
        )
        self.assertEqual(outcome.receipt.status, "CANCELLED")

    def test_a_grandchild_holding_the_pipe_is_killed_and_the_group_is_empty(self) -> None:
        script = (
            "import subprocess,sys,time\n"
            f"subprocess.Popen([{PYTHON!r}, '-c', 'import time; time.sleep(60)'])\n"
            "sys.stdout.write('parent-exiting')\n"
            "sys.stdout.flush()\n"
        )
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", script],
                timeout_ms=1_500,
            )
        )
        # The direct process exits promptly while its descendant keeps running.
        # Under pipe-EOF supervision this looked like a completed command; the
        # capsule reports it as a descendant that outlived its parent, which can
        # never be COMPLETED.
        self.assertEqual(outcome.receipt.status, "FAILED")
        self.assertEqual(
            outcome.tool_result.error_code, "descendant_outlived_the_direct_process"
        )
        process = self.harness.store.load("process-observation", "proposal-1")
        self.assertTrue(process["descendants_alive_at_direct_exit"])
        # Quiescence is verified inside the capsule from ECHILD, not asserted.
        self.assertTrue(process["namespace_quiescent"])
        self.assertTrue(process["descendants_reaped"])
        self.assertGreaterEqual(process["extra_descendants_reaped"], 1)

    def _flood(self, stream: str, chunk: str, repeats: int, *, max_output_bytes: int = 4096):
        return self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", _flood_script(stream, chunk, repeats)],
                timeout_ms=60_000,
                max_output_bytes=max_output_bytes,
            )
        )

    def test_stdout_only_flood_is_bounded_and_fully_counted(self) -> None:
        outcome = self._flood("stdout", "a" * 1024, 2048)
        observation = self.harness.store.load("stdout-observation", "proposal-1")
        self.assertEqual(observation["total_bytes"], 1024 * 2048)
        self.assertEqual(observation["retained_bytes"], 4096)
        self.assertTrue(observation["retained_truncated"])
        self.assertTrue(outcome.tool_result.stdout_truncated)
        self.assertEqual(len(outcome.tool_result.stdout.encode("utf-8")), 4096)

    def test_stderr_only_flood_is_bounded_and_fully_counted(self) -> None:
        self._flood("stderr", "b" * 1024, 2048)
        observation = self.harness.store.load("stderr-observation", "proposal-1")
        self.assertEqual(observation["total_bytes"], 1024 * 2048)
        self.assertEqual(observation["retained_bytes"], 4096)

    def test_simultaneous_stdout_and_stderr_flood_never_deadlocks(self) -> None:
        script = (
            "import sys\n"
            "for _ in range(4096):\n"
            "    sys.stdout.write('o' * 512)\n"
            "    sys.stderr.write('e' * 512)\n"
            "sys.stdout.flush()\nsys.stderr.flush()\n"
        )
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", script],
                timeout_ms=60_000,
                max_output_bytes=8192,
            )
        )
        self.assertEqual(outcome.receipt.status, "COMPLETED")
        for stream in ("stdout", "stderr"):
            observation = self.harness.store.load(f"{stream}-observation", "proposal-1")
            self.assertEqual(observation["total_bytes"], 512 * 4096)
            self.assertEqual(observation["retained_bytes"], 8192)

    def test_a_multi_byte_character_split_by_the_bound_is_trimmed_explicitly(self) -> None:
        outcome = self._flood("stdout", "é", 600, max_output_bytes=1001)
        observation = self.harness.store.load("stdout-observation", "proposal-1")
        self.assertEqual(observation["total_bytes"], 1200)
        self.assertEqual(observation["text_decode_status"], "UTF8_DECODED_AFTER_BOUNDARY_TRIM")
        self.assertEqual(observation["retained_bytes"], 1000)
        self.assertEqual(len(outcome.tool_result.stdout), 500)

    def test_non_utf8_command_output_is_byte_observed_and_the_text_is_refused(self) -> None:
        script = "import sys;sys.stdout.buffer.write(b'\\xff\\xfe\\xfd');sys.stdout.buffer.flush()"
        outcome = self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", script],
                timeout_ms=30_000,
            )
        )
        self.assertEqual(outcome.receipt.status, "FAILED")
        self.assertEqual(outcome.tool_result.error_code, "non_utf8_output")
        observation = self.harness.store.load("stdout-observation", "proposal-1")
        self.assertEqual(observation["total_bytes"], 3)
        self.assertEqual(observation["text_decode_status"], "REFUSED_NON_UTF8")

    def test_resource_observation_never_fabricates_an_unavailable_metric(self) -> None:
        self.harness.run(
            RunCommandRequest.create(
                tool_grammar_fingerprint=self.harness.grammar,
                argv=[PYTHON, "-c", "pass"],
                timeout_ms=30_000,
            )
        )
        observation = self.harness.store.load("resource-observation", "proposal-1")
        for value_name, availability_name in (
            ("child_cpu_user_ms", "child_cpu_user_availability"),
            ("child_max_rss_kib", "child_max_rss_availability"),
        ):
            if observation[availability_name] not in {"OBSERVED", "OBSERVED_BEST_EFFORT"}:
                self.assertIsNone(observation[value_name])
        self.assertEqual(observation["controller_peak_retained_availability"], "OBSERVED")


class GitAndFilesystemObservationTests(unittest.TestCase):
    """Filesystem and Git observations before and after the effect."""

    def setUp(self) -> None:
        self.harness = _Harness().bind()
        self.addCleanup(self.harness.close)

    def test_workspace_without_git_reports_repository_absent(self) -> None:
        self.assertFalse(self.harness.binding.git_present)
        self.assertEqual(self.harness.binding.initial_git_observation.availability, "REPOSITORY_ABSENT")

    @unittest.skipIf(shutil.which("git") is None, "git is unavailable on this host")
    def test_clean_and_dirty_git_worktrees_are_distinguished(self) -> None:
        harness = _Harness(run_id="run-git").bind()
        self.addCleanup(harness.close)
        if not initialise_git_repository(harness.workspace):
            self.skipTest("a disposable git repository could not be created on this host")
        clean = observe_git(harness.workspace, harness.binding.root_fd, phase="INITIAL")
        self.assertEqual(clean.availability, "OBSERVED")
        self.assertFalse(clean.worktree_dirty)
        self.assertFalse(clean.untracked_present)

        harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=harness.grammar, path="tracked.txt", content="mutated\n"
            )
        )
        harness.run(
            WriteFileRequest.create(
                tool_grammar_fingerprint=harness.grammar, path="untracked.txt", content="new\n"
            )
        )
        after = observe_git(harness.workspace, harness.binding.root_fd, phase="AFTER_EFFECT")
        self.assertTrue(after.worktree_dirty)
        self.assertTrue(after.untracked_present)
        self.assertNotEqual(after.status_fingerprint, clean.status_fingerprint)

    def test_filesystem_observations_change_across_a_mutation(self) -> None:
        outcome = self.harness.run(
            WriteFileRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="new.txt", content="x")
        )
        before = self.harness.store.load("filesystem-before", "proposal-1")
        after = self.harness.store.load("filesystem-after", "proposal-1")
        self.assertEqual(before["entry_count"] + 1, after["entry_count"])
        self.assertNotEqual(before["tree_fingerprint"], after["tree_fingerprint"])
        self.assertEqual(outcome.ledger_entry.filesystem_observation_after_fingerprint.to_dict(), after["record_fingerprint"])

    def test_a_read_only_effect_leaves_the_tree_fingerprint_unchanged(self) -> None:
        (self.harness.workspace / "a.txt").write_text("a", encoding="utf-8")
        self.harness.run(ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path="."))
        before = self.harness.store.load("filesystem-before", "proposal-1")
        after = self.harness.store.load("filesystem-after", "proposal-1")
        self.assertEqual(before["tree_fingerprint"], after["tree_fingerprint"])


class ProposalBeforeEffectOrderTests(unittest.TestCase):
    """The instrumented proof that publication precedes every effect."""

    def test_proposal_reservation_and_started_are_durable_at_the_effect_boundary(self) -> None:
        for condition in ("DIRECT", "GOVERNED"):
            with self.subTest(condition=condition):
                harness = _Harness(condition, run_id=f"run-order-{condition.lower()}").bind()
                self.addCleanup(harness.close)
                outcome = harness.run(
                    WriteFileRequest.create(
                        tool_grammar_fingerprint=harness.grammar, path="ordered.txt", content="ordered"
                    )
                )
                self.assertEqual(len(harness.boundary_observations), 1)
                self.assertEqual(
                    harness.boundary_observations[0],
                    tuple(sorted(PRE_EFFECT_OBJECT_KINDS)),
                )
                self.assertEqual(outcome.durable_at_effect_boundary, tuple(sorted(PRE_EFFECT_OBJECT_KINDS)))

    def test_a_governed_refusal_never_reaches_the_effect_boundary(self) -> None:
        for refusal in ("REFUSE", "TERMINATE_RUN", "REQUIRE_CONTINUATION"):
            with self.subTest(decision=refusal):
                harness = _Harness("GOVERNED", run_id=f"run-refuse-{refusal.lower()}").bind()
                self.addCleanup(harness.close)
                outcome = harness.run(
                    WriteFileRequest.create(
                        tool_grammar_fingerprint=harness.grammar, path="never.txt", content="never"
                    ),
                    governed_decision=refusal,
                )
                self.assertEqual(outcome.receipt.status, "REFUSED")
                self.assertFalse(outcome.effect_crossed_boundary)
                self.assertEqual(harness.substrate.effect_invocation_count, 0)
                self.assertEqual(harness.boundary_observations, [])
                self.assertFalse((harness.workspace / "never.txt").exists())
                self.assertEqual(harness.store.inspect(OBJECT_KIND_RESERVATION, "proposal-1").state, "ABSENT")
                self.assertEqual(harness.store.inspect(OBJECT_KIND_LIFECYCLE_STARTED, "proposal-1").state, "ABSENT")
                self.assertEqual(harness.store.inspect(OBJECT_KIND_PROPOSAL, "proposal-1").state, "PUBLISHED")


class SharedExecutorIdentityTests(unittest.TestCase):
    """EXEC-05: one executor implementation serves both typed decisions."""

    def _traced_execution(self, condition: str) -> tuple[set[tuple[str, int]], object]:
        harness = _Harness(condition, run_id=f"run-trace-{condition.lower()}").bind()
        self.addCleanup(harness.close)
        executed: set[tuple[str, int]] = set()
        target = os.path.abspath(sys.modules["admissible.paired_runner.effects"].__file__)

        def tracer(frame, event, argument):
            if frame.f_code.co_filename == target:
                executed.add((frame.f_code.co_name, frame.f_lineno))
                return tracer
            return None

        sys.settrace(tracer)
        try:
            outcome = harness.run(
                WriteFileRequest.create(
                    tool_grammar_fingerprint=harness.grammar, path="shared.txt", content="shared bytes"
                )
            )
        finally:
            sys.settrace(None)
        return executed, outcome

    def test_the_post_decision_path_is_the_same_object_and_the_same_branches(self) -> None:
        direct_lines, direct_outcome = self._traced_execution("DIRECT")
        governed_lines, governed_outcome = self._traced_execution("GOVERNED")

        post_decision = {"_execute_permitted_effect", "_cross_effect_boundary", "_write_file", "_terminal_receipt"}
        direct_post = {item for item in direct_lines if item[0] in post_decision}
        governed_post = {item for item in governed_lines if item[0] in post_decision}
        self.assertEqual(direct_post, governed_post)
        self.assertTrue(direct_post)

        # The executor is literally one implementation, not two that agree.
        self.assertIs(
            type(direct_outcome).__module__, type(governed_outcome).__module__
        )
        self.assertIs(
            SharedEffectSubstrate._execute_permitted_effect.__code__,
            SharedEffectSubstrate._execute_permitted_effect.__code__,
        )

    def test_direct_and_governed_allow_produce_identical_effect_evidence(self) -> None:
        results = {}
        for condition in ("DIRECT", "GOVERNED"):
            harness = _Harness(condition, run_id=f"run-parity-{condition.lower()}").bind()
            self.addCleanup(harness.close)
            outcome = harness.run(
                WriteFileRequest.create(
                    tool_grammar_fingerprint=harness.grammar, path="parity.txt", content="identical bytes"
                )
            )
            results[condition] = outcome
            self.assertEqual(outcome.receipt.status, "COMPLETED")
        direct, governed = results["DIRECT"], results["GOVERNED"]
        self.assertEqual(direct.tool_result.to_dict(), governed.tool_result.to_dict())
        self.assertEqual(direct.receipt.tool_request_fingerprint, governed.receipt.tool_request_fingerprint)
        self.assertEqual(direct.receipt.effect_classification, governed.receipt.effect_classification)
        self.assertEqual(direct.ledger_entry.effect_classification, governed.ledger_entry.effect_classification)
        self.assertEqual(direct.ledger_entry.decision_value, "DIRECT_EXECUTION")
        self.assertEqual(governed.ledger_entry.decision_value, "ALLOW")

    def test_the_substrate_refuses_a_decision_taken_on_another_proposal(self) -> None:
        harness = _Harness("GOVERNED", run_id="run-mismatch").bind()
        self.addCleanup(harness.close)
        request = ListFilesRequest.create(tool_grammar_fingerprint=harness.grammar, path=".")
        proposal = build_proposal(harness.specification, request, proposal_id="proposal-a")
        other = build_proposal(harness.specification, request, proposal_id="proposal-b")
        decision = decision_for(other)
        with self.assertRaises(ValueError):
            harness.substrate.execute(
                specification=harness.specification,
                proposal=proposal,
                decision=decision,
                reservation_id="reservation-x",
                receipt_id="receipt-x",
            )


class TypedResultBindingTests(unittest.TestCase):
    """A result that does not answer its exact request is refused."""

    def setUp(self) -> None:
        self.harness = _Harness().bind()
        self.addCleanup(self.harness.close)

    def test_a_result_bound_to_a_different_request_is_refused(self) -> None:
        request = ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".")
        other = ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".", max_entries=5)
        result = ListFilesResult.create(request_fingerprint=request.request_fingerprint, entries=())
        result.validate_for_request(request)
        with self.assertRaises(ValueError):
            result.validate_for_request(other)

    def test_a_receipt_bound_to_a_foreign_result_is_refused(self) -> None:
        (self.harness.workspace / "a.txt").write_text("a", encoding="utf-8")
        outcome = self.harness.run(
            ListFilesRequest.create(tool_grammar_fingerprint=self.harness.grammar, path=".")
        )
        foreign_specification = build_specification("GOVERNED", run_id="run-foreign")
        foreign_request = ListFilesRequest.create(
            tool_grammar_fingerprint=foreign_specification.tool_grammar.grammar_fingerprint, path="."
        )
        foreign_proposal = build_proposal(foreign_specification, foreign_request, proposal_id="proposal-foreign")
        with self.assertRaises(ValueError):
            outcome.receipt.validate_for_causal_chain(
                specification=foreign_specification,
                proposal=foreign_proposal,
                decision=decision_for(foreign_proposal),
                reservation=outcome.reservation,
            )


class DurablePublicationTests(unittest.TestCase):
    """The exact publication state taxonomy."""

    def setUp(self) -> None:
        self.disposable = DisposableWorkspace()
        self.addCleanup(self.disposable.close)
        self.store = DurableObjectStore(self.disposable.store_root)

    def test_absent_published_and_duplicate_identical_states(self) -> None:
        self.assertEqual(self.store.inspect("thing", "one").state, "ABSENT")
        first = self.store.publish(object_kind="thing", object_id="one", payload={"a": 1})
        self.assertEqual(first.state, "PUBLISHED")
        self.assertTrue(first.verified_bytes)
        second = self.store.publish(object_kind="thing", object_id="one", payload={"a": 1})
        self.assertEqual(second.state, "DUPLICATE_IDENTICAL")
        self.assertEqual(second.content_fingerprint, first.content_fingerprint)

    def test_a_different_object_for_the_same_identity_is_a_conflict(self) -> None:
        self.store.publish(object_kind="thing", object_id="one", payload={"a": 1})
        with self.assertRaises(PublicationConflict):
            self.store.publish(object_kind="thing", object_id="one", payload={"a": 2})
        self.assertEqual(self.store.load("thing", "one"), {"a": 1})

    def test_corrupt_committed_bytes_fail_closed(self) -> None:
        self.store.publish(object_kind="thing", object_id="one", payload={"a": 1})
        path = self.store.path_of("thing", "one")
        path.write_bytes(b"{not canonical")
        self.assertEqual(self.store.inspect("thing", "one").state, "CORRUPT")
        with self.assertRaises(CorruptDurableObject):
            self.store.load("thing", "one")
        with self.assertRaises(CorruptDurableObject):
            self.store.publish(object_kind="thing", object_id="one", payload={"a": 1})

    def test_published_objects_use_restrictive_modes_and_leave_no_temporary(self) -> None:
        self.store.publish(object_kind="thing", object_id="one", payload={"a": 1})
        mode = os.stat(self.store.path_of("thing", "one")).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        self.assertEqual(self.store.partial_publications(), ())

    def test_the_store_root_must_be_absolute_and_canonical(self) -> None:
        with self.assertRaises(ValueError):
            DurableObjectStore("relative/store")
        link = Path(self.disposable.root) / "store-link"
        os.symlink(self.disposable.store_root, link)
        with self.assertRaises(ValueError):
            DurableObjectStore(link)


if __name__ == "__main__":
    unittest.main()
