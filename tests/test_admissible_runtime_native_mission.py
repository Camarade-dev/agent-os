from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

import admissible.delegated_gate.native_canary as native_canary_module

from test_admissible_delegated_gate_native_executor import (
    Clock,
    FakeNativeProcessRunner,
    _commit,
    _injected_test_cursor,
)

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.mission_profile import (
    GitEndStatePolicy,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    NativeMissionProfile,
    ProfileCheckpointCommand,
    RuntimePromptAuthority,
    VerificationAuthority,
    VerificationMode,
    WorkspaceSourceAuthority,
    WorkspaceSourceKind,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.models import EvidenceKind
from admissible.delegated_gate.native_canary import (
    InitializedWorkspaceIdentity,
    NativeCanaryCoordinator,
    NativeCanaryStatus,
    NativeEvidenceInvalid,
    ProductVerdict,
    RUN_PREFLIGHT_METADATA_FILE_NAME,
    _write_run_metadata_once,
    _filesystem_byte_inventory_hash,
    _inspect_runtime_git_metadata,
    _materialize_local_repository_copy,
    _observe_local_repository_source,
    _parse_local_git_config,
    build_native_agent_prompt,
    build_parser,
    build_profile_authorization_payload,
    create_canary_session,
    legacy_canary_profile,
    materialize_authorized_workspace,
    observe_initialized_workspace_identity,
    reconstruct_completed_native_mission,
    registered_profiles,
    run_native_mission_application,
)
from admissible.delegated_gate.native_executor import (
    AtomicNativeExecutionStore,
    NativeDelegatedExecutor,
    _hardened_git_environment,
)
from admissible.delegated_gate.store import AtomicDelegatedSessionStore


LEGACY_IDENTITIES = {
    "act-2a-high-score-canary-v1": "4e4f4672a5181ee178dc20d7a7c04865a2789f9430793dd882048cc802f78d57",
    "incident-replay-v1": "ceac9c5dc344d7f5b5d24c530cd28a29012c3dcbb0f4fa7906884caec6845bc3",
    "workflow-recovery-v1": "ed67459c803bf439ee3325cdf9fa069d48677408412ff283ab86a4234d9ae2f8",
    "workflow-recovery-v2": "e4bdcf5a2f5ae1cae6435bc8881eff40e6154762e9cbd76c6054bd0e61e78724",
    "neon-siege-v1": "da7a93272544a05b60887973a80c72e2541104053162646c5daa5a30920a5b35",
    # NEON_RELAY_PREP_2 deliberately extends this exact pin rather than
    # weakening it: the registered set is still asserted by equality, and the
    # five identities above are unchanged.  neon-relay-v1 is the first
    # registered runtime-v2 profile whose workspace source is an existing local
    # Git repository; its own complete identity is pinned in
    # tests/test_admissible_neon_relay_profile.py.
    "neon-relay-v1": "8ef57625f3fb369ff87d2981ff15753fcd45f0328c74bcb05ed81c8a61c9999d",
    # The ACP transport repair likewise extends the pin instead of weakening
    # it: every identity above is unchanged, and neon-relay-v1 in particular is
    # byte-identical.  neon-relay-v2 is the same mission on a new run identity
    # and the ACP_STDIO prompt transport, because v1's argv transport is
    # unspawnable on Windows and v1's single native attempt is durably consumed.
    "neon-relay-v2": "3dd4ce6198e450b420afab4ed1e19acfcb7e807e292d87cafdc475ad0ca2c3b6",
    # The backend-drift repair extends the pin once more: neon-relay-v3 is the
    # same mission and the same ACP_STDIO transport on a third run identity,
    # because v2's single native attempt is durably consumed by the authorized
    # run that crashed inside drift observation.
    "neon-relay-v3": "d871015d5a0ca8fc1ed050264a5c30845162cce8396fae6fa5fa2f0352253ec6",
}


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        env=environment,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and completed.returncode:
        raise AssertionError(completed.stderr)
    return completed


def _repository(root: Path, *, remote: bool = False) -> Path:
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.name", "Runtime Test")
    _git(root, "config", "user.email", "runtime@test.invalid")
    _git(root, "config", "core.autocrlf", "false")
    (root / "README.md").write_text("runtime source\n", encoding="utf-8", newline="\n")
    _git(root, "add", "README.md")
    _git(root, "commit", "--quiet", "-m", "chore: initialize runtime source")
    if remote:
        _git(root, "remote", "add", "origin", str(root.parent / "never-contact"))
    return root.resolve()


def _profile(
    repository: Path,
    *,
    mode: VerificationMode = VerificationMode.OBSERVED_ONLY,
    profile_id: str = "runtime-observed-v2",
    checkpoint_exit_code: int | None = None,
    frozen_source: str = "console.log('owner-frozen acceptance passed');",
) -> NativeMissionProfile:
    source = WorkspaceSourceAuthority(
        kind=WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY,
        local_repository_path=str(repository.resolve()),
    )
    verifier = (
        VerificationAuthority(
            mode=mode,
            verifier_source=None,
            verifier_source_sha256=None,
            verifier_timeout_seconds=None,
            verifier_output_limit_bytes=None,
            disclose_complete_source=False,
        )
        if mode is VerificationMode.OBSERVED_ONLY
        else VerificationAuthority(
            mode=mode,
            verifier_source=frozen_source,
            verifier_source_sha256=hashlib.sha256(frozen_source.encode("utf-8")).hexdigest(),
            verifier_timeout_seconds=30,
            verifier_output_limit_bytes=4096,
            disclose_complete_source=True,
        )
    )
    checkpoint_commands = (
        ()
        if checkpoint_exit_code is None
        else (
            ProfileCheckpointCommand(
                command_id="runtime-checkpoint",
                argv=(sys.executable, "-c", f"raise SystemExit({checkpoint_exit_code})"),
                timeout_seconds=30,
                max_capture_bytes=4096,
            ),
        )
    )
    evidence_kinds = [EvidenceKind.TARGET_TREE.value, EvidenceKind.GIT_STATE.value]
    if checkpoint_commands:
        evidence_kinds.append(EvidenceKind.VERIFICATION_COMMAND.value)
    return create_native_mission_profile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
        profile_id=profile_id,
        run_id=f"{profile_id}-run",
        session_id=f"{profile_id}-run",
        gate_id=f"{profile_id}-gate",
        mission_id=f"{profile_id}-mission",
        mission_text="Add a deterministic runtime marker and commit it exactly once.",
        gate_objective="Create the configured marker under the strict local-only contract.",
        gate_clauses=(("runtime.material", "The configured marker is present."),),
        required_evidence_kinds=tuple(evidence_kinds),
        checkpoint_commands=checkpoint_commands,
        completion_conditions_text="Complete the material and Git policy, then stop.",
        budgets=(1, 1, 0, 0, 0),
        timeout_seconds=60,
        stdout_byte_limit=8192,
        stderr_byte_limit=8192,
        model="auto",
        workspace_source=source,
        git_end_state_policy=GitEndStatePolicy(
            required_commits_added=1,
            required_complete_commit_message="feat: add runtime marker",
            final_worktree_clean=True,
            final_index_clean=True,
            final_remotes_absent=True,
            required_material_paths=("README.md",),
        ),
        verification=verifier,
        runtime_prompt=RuntimePromptAuthority(
            permitted_effects=("Edit and commit files only in the assigned workspace.",),
            forbidden_effects=("Do not use network, add remotes, push, deploy, or edit the source repository.",),
            stop_clause="Stop immediately after the exact one-commit policy and configured checkpoints pass.",
        ),
    )


def _rewrite_profile(data: dict, mutation) -> dict:
    changed = json.loads(json.dumps(data))
    mutation(changed)
    body = {key: value for key, value in changed.items() if key != "profile_fingerprint"}
    changed["profile_fingerprint"] = fingerprint(body)
    return changed


def test_all_registered_v1_profile_and_workflow_prompt_identities_are_immutable():
    profiles = registered_profiles()
    assert {key: value.profile_fingerprint for key, value in profiles.items()} == LEGACY_IDENTITIES
    expected_prompts = {
        "workflow-recovery-v1": (7786, "6e73f1dbeebf65772caad08e21d38b3225f39b6bfd22384f7c447e06a826e3ef"),
        "workflow-recovery-v2": (9109, "440523b407b804baf9015c68bf6c9aa70ac8796c304f4bf4afb16efb10f14cd3"),
    }
    for profile_id, (size, digest) in expected_prompts.items():
        profile = profiles[profile_id]
        workspace = Path(r"C:\Users\stris\Documents\Projets\ENTRE") / profile.run_id / "work"
        state = create_canary_session(session_id=profile.session_id, profile=profile)
        with mock.patch(
            "admissible.delegated_gate.native_canary._safe_directory",
            return_value=(workspace, None),
        ):
            prompt = build_native_agent_prompt(
                mission=state.mission,
                gate_contract=state.current_gate,
                work_workspace=workspace,
                required_commit_message=profile.required_commit_message,
                completion_conditions=profile.completion_conditions_text,
                profile=profile,
            )
        assert (len(prompt.encode("utf-8")), hashlib.sha256(prompt.encode("utf-8")).hexdigest()) == (
            size,
            digest,
        )
    assert legacy_canary_profile().to_dict()["schema_version"] == "admissible_native_mission_profile_v1"


@pytest.mark.parametrize("mode", [VerificationMode.OBSERVED_ONLY, VerificationMode.FROZEN_BEHAVIORAL])
def test_runtime_profile_document_exact_round_trip_and_prompt_disclosure(tmp_path: Path, mode: VerificationMode):
    repository = _repository(tmp_path / "source")
    profile = _profile(repository, mode=mode, profile_id=f"runtime-{mode.value.lower()}-v2")
    document = tmp_path / f"{mode.value}.json"
    document.write_bytes(canonical_bytes(profile.to_dict()) + b"\n")
    loaded = load_native_mission_profile_document(document.resolve())
    assert loaded == profile
    assert NativeMissionProfile.from_dict(json.loads(json.dumps(profile.to_dict()))) == profile
    assert profile.profile_fingerprint == fingerprint(profile._body())
    workspace = tmp_path / "prompt-work"
    workspace.mkdir()
    state = create_canary_session(session_id=profile.session_id, profile=profile)
    prompt = build_native_agent_prompt(
        mission=state.mission,
        gate_contract=state.current_gate,
        work_workspace=workspace,
        profile=profile,
    )
    for required in (
        str(workspace.resolve()),
        "Required material paths:",
        "Exact Git end-state policy:",
        "Execution budgets:",
        "Checkpoint commands and bounds:",
        f"Verification mode: {mode.value}",
        "Exact stop clause:",
    ):
        assert required in prompt
    if mode is VerificationMode.OBSERVED_ONLY:
        assert "Behavior was not independently verified." in prompt
        assert "will not\nindependently verify the requested behavior" in prompt
        assert "OWNER-FROZEN" not in prompt
    else:
        assert profile.verifier_source in prompt
        assert "BEGIN OWNER-FROZEN BEHAVIORAL VERIFIER" in prompt
        assert profile.verifier_source_sha256 in prompt


def test_runtime_document_loader_rejects_unknown_extra_tamper_duplicates_and_relative_path(tmp_path: Path):
    repository = _repository(tmp_path / "source")
    profile = _profile(repository)
    valid = profile.to_dict()
    cases = []
    cases.append({**valid, "schema_version": "admissible_native_mission_profile_v99"})
    cases.append({**valid, "extra": True})
    cases.append({**valid, "profile_fingerprint": "0" * 64})
    for index, data in enumerate(cases):
        path = tmp_path / f"invalid-{index}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError):
            load_native_mission_profile_document(path.resolve())
    duplicate = tmp_path / "duplicate.json"
    text = json.dumps(valid)
    duplicate.write_text(text.replace("{", '{"profile_id":"duplicate",', 1), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_native_mission_profile_document(duplicate.resolve())
    with pytest.raises(ValueError, match="absolute"):
        load_native_mission_profile_document(Path("relative.json"))


def test_runtime_schema_rejects_invalid_verification_and_workspace_combinations(tmp_path: Path):
    repository = _repository(tmp_path / "source")
    profile = _profile(repository)
    invalid_observed = _rewrite_profile(
        profile.to_dict(),
        lambda data: data["verification"].update(
            verifier_source="console.log('hidden')",
            verifier_source_sha256=hashlib.sha256(b"console.log('hidden')").hexdigest(),
            verifier_timeout_seconds=1,
            verifier_output_limit_bytes=1,
        ),
    )
    with pytest.raises(ValueError, match="observed-only"):
        NativeMissionProfile.from_dict(invalid_observed)
    frozen = _profile(repository, mode=VerificationMode.FROZEN_BEHAVIORAL)
    invalid_digest = _rewrite_profile(
        frozen.to_dict(), lambda data: data["verification"].update(verifier_source_sha256="0" * 64)
    )
    with pytest.raises(ValueError, match="digest"):
        NativeMissionProfile.from_dict(invalid_digest)
    invalid_source = _rewrite_profile(
        profile.to_dict(),
        lambda data: data["workspace_source"].update(fixture_id="not-allowed"),
    )
    with pytest.raises(ValueError, match="fixture"):
        NativeMissionProfile.from_dict(invalid_source)
    relative = _rewrite_profile(
        profile.to_dict(),
        lambda data: data["workspace_source"].update(local_repository_path="relative/repo"),
    )
    with pytest.raises(ValueError, match="absolute"):
        NativeMissionProfile.from_dict(relative)
    unsafe_history = _rewrite_profile(
        profile.to_dict(),
        lambda data: data["git_end_state_policy"].update(required_commits_added=2),
    )
    with pytest.raises(ValueError, match="commits"):
        NativeMissionProfile.from_dict(unsafe_history)
    unsafe_boolean = _rewrite_profile(
        profile.to_dict(),
        lambda data: data["git_end_state_policy"].update(final_index_clean="true"),
    )
    with pytest.raises(ValueError, match="boolean"):
        NativeMissionProfile.from_dict(unsafe_boolean)


def test_profile_id_and_document_are_mutually_exclusive_at_cli_parse():
    flags = [
        "--source-repository", "source",
        "--required-source-head", "0" * 40,
        "--run-root", "run",
        "--run-id", "run-id",
        "--session-id", "run-id",
        "--executable", "cursor-agent",
        "--profile-id", "workflow-recovery-v1",
        "--profile-document", "profile.json",
    ]
    with pytest.raises(SystemExit):
        build_parser().parse_args(flags)


def test_programmatic_entry_requires_one_profile_authority_and_uses_id_guards(tmp_path: Path):
    source = _repository(tmp_path / "source")
    profile = _profile(source)
    common = dict(
        source_repository=source,
        required_source_head=_git(source, "rev-parse", "HEAD").stdout.strip(),
        run_root=tmp_path / "wrong-run",
        run_id="wrong-run",
        session_id="wrong-run",
        executable=sys.executable,
    )
    with pytest.raises(ValueError, match="exactly one"):
        run_native_mission_application(**common)
    document = tmp_path / "profile.json"
    document.write_bytes(canonical_bytes(profile.to_dict()) + b"\n")
    with pytest.raises(ValueError, match="exactly one"):
        run_native_mission_application(
            **common,
            profile=profile,
            profile_document=document.resolve(),
        )
    with mock.patch(
        "admissible.delegated_gate.native_canary.preflight_native_cursor",
        side_effect=AssertionError("ID mismatch must block before backend probe"),
    ):
        assert run_native_mission_application(**common, profile=profile) == 2


def test_local_repository_materialization_is_isolated_remote_free_and_source_unchanged(tmp_path: Path):
    repository = _repository(tmp_path / "source")
    profile = _profile(repository)
    source_before = _observe_local_repository_source(repository)
    destination = tmp_path / "destination"
    destination.mkdir()
    built, identity = _materialize_local_repository_copy(
        profile=profile, destination_parent=destination, repository_name="work"
    )
    source_after = _observe_local_repository_source(repository)
    assert source_after == source_before
    assert identity.initial_git_head == source_before.head
    assert identity.initial_material_tree_hash == source_before.material_tree_hash
    assert identity.source_kind == WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY.value
    assert _git(built.repository, "status", "--porcelain=v1", "--untracked-files=all").stdout == ""
    assert _git(built.repository, "diff", "--cached", "--name-only").stdout == ""
    assert _git(built.repository, "remote").stdout.strip() == ""
    assert (built.repository / ".git").resolve() != (repository / ".git").resolve()
    assert _git(built.repository, "rev-parse", "HEAD").stdout.strip() == source_before.head
    assert list((built.repository / ".git" / "hooks").iterdir()) == []
    assert not os.path.samefile(
        repository / ".git" / "objects", built.repository / ".git" / "objects"
    )
    assert not os.path.samefile(
        repository / ".git" / "index", built.repository / ".git" / "index"
    )
    local_keys = set(
        _git(built.repository, "config", "--local", "--name-only", "--list").stdout.splitlines()
    )
    assert local_keys <= {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.symlinks",
        "core.ignorecase",
        "core.precomposeunicode",
        "core.autocrlf",
        "core.safecrlf",
        "core.hookspath",
        "extensions.objectformat",
        "extensions.refstorage",
        "user.name",
        "user.email",
        "commit.gpgsign",
        "tag.gpgsign",
    }
    assert {
        "core.hookspath",
        "user.name",
        "user.email",
        "commit.gpgsign",
        "tag.gpgsign",
    } <= local_keys


def _sentinel_command(path: Path, sentinel: Path) -> Path:
    path.write_text(
        f'@echo off\r\n>"{sentinel}" echo GIT_METADATA_EXECUTED\r\nexit /b 0\r\n',
        encoding="utf-8",
        newline="",
    )
    return path


def _sentinel_hook(path: Path, sentinel: Path) -> Path:
    path.write_text(
        f'#!/bin/sh\nprintf GIT_METADATA_EXECUTED > "{sentinel.as_posix()}"\n',
        encoding="utf-8",
        newline="\n",
    )
    return path


def _assert_source_metadata_rejected_before_git(
    *, repository: Path, profile: NativeMissionProfile, scratch: Path
) -> None:
    before = _filesystem_byte_inventory_hash(repository)
    scratch.mkdir()
    original_text_git = native_canary_module._git_read_only
    original_binary_git = native_canary_module._git_binary_read_only
    with mock.patch(
        "admissible.delegated_gate.native_canary._git_read_only",
        side_effect=original_text_git,
    ) as text_git, mock.patch(
        "admissible.delegated_gate.native_canary._git_binary_read_only",
        side_effect=original_binary_git,
    ) as binary_git:
        with pytest.raises(NativeEvidenceInvalid, match="Git|hook|config|attributes"):
            with mock.patch(
                "admissible.delegated_gate.native_canary.tempfile.mkdtemp",
                return_value=str(scratch),
            ):
                observe_initialized_workspace_identity(profile)
    assert text_git.call_count == 0
    assert binary_git.call_count == 0
    assert not scratch.exists()
    assert _filesystem_byte_inventory_hash(repository) == before


def test_local_repository_direct_hook_rejects_before_git_and_cleans_scratch(tmp_path: Path):
    repository = _repository(tmp_path / "source")
    sentinel = tmp_path / "direct-hook-sentinel.txt"
    _sentinel_hook(repository / ".git" / "hooks" / "pre-commit", sentinel)
    _assert_source_metadata_rejected_before_git(
        repository=repository,
        profile=_profile(repository, profile_id="direct-hook-v2"),
        scratch=tmp_path / "direct-hook-scratch",
    )
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "attack",
    [
        "external-hooks-path",
        "fsmonitor",
        "include-path",
        "includeif-path",
        "shell-alias",
        "filter-clean",
        "filter-process",
        "diff-textconv",
        "credential-helper",
        "gpg-program",
        "external-attributes-file",
    ],
)
def test_local_repository_command_config_rejects_before_any_git(
    tmp_path: Path, attack: str
):
    repository = _repository(tmp_path / "source")
    sentinel = tmp_path / f"{attack}-sentinel.txt"
    command = _sentinel_command(tmp_path / f"{attack}.cmd", sentinel)
    external_config = tmp_path / "external.gitconfig"
    external_config.write_text(
        f'[core]\n\tfsmonitor = "{command.as_posix()}"\n',
        encoding="utf-8",
        newline="\n",
    )
    if attack == "external-hooks-path":
        hooks = tmp_path / "external-hooks"
        hooks.mkdir()
        _sentinel_hook(hooks / "pre-commit", sentinel)
        _git(repository, "config", "core.hooksPath", str(hooks))
    elif attack == "fsmonitor":
        _git(repository, "config", "CoRe.FsMoNiToR", str(command))
    elif attack == "include-path":
        _git(repository, "config", "include.path", str(external_config))
    elif attack == "includeif-path":
        _git(
            repository,
            "config",
            f"includeIf.gitdir:{repository.as_posix()}/.path",
            str(external_config),
        )
    elif attack == "shell-alias":
        _git(repository, "config", "alias.evil", f"!{command}")
    elif attack == "filter-clean":
        _git(repository, "config", "filter.attack.clean", str(command))
    elif attack == "filter-process":
        _git(repository, "config", "filter.attack.process", str(command))
    elif attack == "diff-textconv":
        _git(repository, "config", "diff.attack.textconv", str(command))
    elif attack == "credential-helper":
        _git(repository, "config", "credential.helper", f"!{command}")
    elif attack == "gpg-program":
        _git(repository, "config", "gpg.program", str(command))
    elif attack == "external-attributes-file":
        attributes = tmp_path / "external.attributes"
        attributes.write_text("* filter=attack\n", encoding="utf-8", newline="\n")
        _git(repository, "config", "core.attributesFile", str(attributes))
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(attack)
    _assert_source_metadata_rejected_before_git(
        repository=repository,
        profile=_profile(repository, profile_id=f"attack-{attack}-v2"),
        scratch=tmp_path / f"{attack}-scratch",
    )
    assert not sentinel.exists()


def test_conservative_source_config_original_comment_backslash_exploit_rejects_before_git(
    tmp_path: Path,
):
    """The bounded v0 grammar rejects the confirmed physical-line smuggling exploit."""

    repository = _repository(tmp_path / "source")
    (repository / ".gitattributes").write_text("* filter=safe\n", encoding="utf-8", newline="\n")
    (repository / "filtered.txt").write_text("tracked\n", encoding="utf-8", newline="\n")
    _git(repository, "add", ".gitattributes", "filtered.txt")
    _git(repository, "commit", "--quiet", "-m", "test: add filtered material")
    sentinel = tmp_path / "original-exploit-sentinel.txt"
    script = tmp_path / "evil-script"
    script.write_text(
        f'#!/bin/sh\nprintf GIT_METADATA_EXECUTED > "{sentinel.as_posix()}"\ncat\n',
        encoding="utf-8",
        newline="\n",
    )
    config = repository / ".git" / "config"
    config.write_bytes(
        (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = false\n"
            "\tbare = false\n"
            "\tlogallrefupdates = true\n"
            "[filter \"safe\"]\n"
            "\trequired = false # \\\n"
            f"\tclean = sh {script.as_posix()}\n"
        ).encode("utf-8")
    )
    source_before = _filesystem_byte_inventory_hash(repository)
    original_text_git = native_canary_module._git_read_only
    original_binary_git = native_canary_module._git_binary_read_only
    with mock.patch(
        "admissible.delegated_gate.native_canary._git_read_only",
        side_effect=original_text_git,
    ) as text_git, mock.patch(
        "admissible.delegated_gate.native_canary._git_binary_read_only",
        side_effect=original_binary_git,
    ) as binary_git:
        with pytest.raises(NativeEvidenceInvalid, match="continuation"):
            _observe_local_repository_source(repository)
    assert text_git.call_count == 0
    assert binary_git.call_count == 0
    scratch = tmp_path / "original-exploit-scratch"
    _assert_source_metadata_rejected_before_git(
        repository=repository,
        profile=_profile(repository, profile_id="original-comment-backslash-v2"),
        scratch=scratch,
    )
    assert not sentinel.exists()
    assert not scratch.exists()
    assert not (tmp_path / "target").exists()
    assert _filesystem_byte_inventory_hash(repository) == source_before


_SMUGGLED_CONFIG_ENTRIES = (
    ('[filter "safe"]', "clean = sh evil-script"),
    ("[core]", "fsmonitor = evil-script"),
    ("[include]", "path = evil-config"),
    ('[includeIf "gitdir:example"]', "path = evil-config"),
    ("[core]", "hooksPath = evil-hooks"),
    ("[credential]", "helper = !evil-script"),
    ("[alias]", "evil = !evil-script"),
)


@pytest.mark.parametrize(("section", "entry"), _SMUGGLED_CONFIG_ENTRIES)
@pytest.mark.parametrize("comment", ("#", ";"))
@pytest.mark.parametrize(
    "layout",
    ("immediate", "blank", "other-section", "benign-duplicates"),
)
def test_conservative_source_config_rejects_comment_backslash_smuggling_before_git(
    tmp_path: Path, section: str, entry: str, comment: str, layout: str
):
    repository = _repository(tmp_path / "source")
    prefix = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n"
    between = {
        "immediate": "",
        "blank": "\n",
        "other-section": "[user]\n\tname = Benign User\n",
        "benign-duplicates": "[core]\n\tfilemode = false\n\tfilemode = false\n",
    }[layout]
    separator = "\t" if layout in {"other-section", "benign-duplicates"} else "    "
    (repository / ".git" / "config").write_bytes(
        (prefix + f"{separator}{comment} concealed {separator}\\\r\n" + between + section + "\r\n\t" + entry + "\r\n").encode("utf-8")
    )
    _assert_source_metadata_rejected_before_git(
        repository=repository,
        profile=_profile(repository, profile_id=f"smuggling-{comment.encode().hex()}-{layout}-v2"),
        scratch=tmp_path / "scratch",
    )


@pytest.mark.parametrize(
    "malformed",
    (
        b"[core]\nfilemode = false\\\n",
        b"[core]\nfilemode = false\\\n bare = false\n",
        b'[core]\nfilemode = "false\\\ntrue"\n',
        b"[core]\nfilemode = false # comment\n",
        b'[core]\nfilemode = "false\n',
        b"[core]\nfilemode = false\\#ambiguous\n",
        b"[core] filemode = false\n",
        b"[remote.origin]\nurl = nowhere\n",
        b"[core]\nfilemode = false\x00\n",
        b"filemode = false\n",
        b"[core]\nfilemode\n",
    ),
)
def test_conservative_source_config_rejects_ambiguous_physical_syntax_before_git(
    tmp_path: Path, malformed: bytes
):
    repository = _repository(tmp_path / "source")
    (repository / ".git" / "config").write_bytes(malformed)
    _assert_source_metadata_rejected_before_git(
        repository=repository,
        profile=_profile(repository, profile_id=f"malformed-{hashlib.sha256(malformed).hexdigest()[:8]}-v2"),
        scratch=tmp_path / "scratch",
    )


def test_conservative_source_config_rejects_size_and_entry_bounds_before_git(tmp_path: Path):
    oversized = _repository(tmp_path / "oversized")
    (oversized / ".git" / "config").write_bytes(b"#" + b"x" * (1024 * 1024))
    _assert_source_metadata_rejected_before_git(
        repository=oversized,
        profile=_profile(oversized, profile_id="oversized-config-v2"),
        scratch=tmp_path / "oversized-scratch",
    )
    excessive = _repository(tmp_path / "excessive")
    (excessive / ".git" / "config").write_text(
        "[core]\n" + "\n".join("filemode = false" for _ in range(10_001)) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _assert_source_metadata_rejected_before_git(
        repository=excessive,
        profile=_profile(excessive, profile_id="excessive-config-v2"),
        scratch=tmp_path / "excessive-scratch",
    )


@pytest.mark.parametrize(
    ("section", "entry"),
    (
        ('[gpg "ssh"]', "defaultKeyCommand = evil"),
        ("[uploadpack]", "packObjectsHook = evil"),
        ('[credential "https://example"]', "oauthRefreshToken = evil"),
        ('[credential "https://example"]', "helper = evil"),
        ('[credential "https://example"]', "tokenCommand = evil"),
        # remote.<name>.url / .fetch and branch.<name>.remote / .merge are inert
        # source metadata and are admitted by
        # tests/test_admissible_source_inert_git_metadata.py.  Their
        # command-bearing and push-bearing siblings stay refused here.
        ('[remote "origin"]', "pushurl = https://example.invalid/repo"),
        ('[remote "origin"]', "uploadpack = evil"),
        ('[remote "origin"]', "receivepack = evil"),
        ('[remote "origin"]', "proxy = http://example.invalid:8080"),
        ('[branch "main"]', "rebase = true"),
        ('[branch "main"]', "pushRemote = origin"),
        ('[url "https://example.invalid/"]', "insteadOf = https://real.invalid/"),
    ),
)
def test_source_allowlist_rejects_adjacent_behavior_keys_before_git(
    tmp_path: Path, section: str, entry: str
):
    repository = _repository(tmp_path / "source")
    (repository / ".git" / "config").write_text(
        f"[core]\nrepositoryformatversion = 0\n{section}\n{entry}\n",
        encoding="utf-8",
        newline="\n",
    )
    _assert_source_metadata_rejected_before_git(
        repository=repository,
        profile=_profile(repository, profile_id=f"allowlist-{hashlib.sha256(entry.encode()).hexdigest()[:8]}-v2"),
        scratch=tmp_path / "scratch",
    )


def test_conservative_source_config_safe_samples_match_hardened_git_oracle(tmp_path: Path):
    repository = _repository(tmp_path / "source")
    config = repository / ".git" / "config"
    config.write_bytes(
        b"\xef\xbb\xbf# simple bounded source config\r\n"
        b"[core]\r\n"
        b"\trepositoryformatversion = 0\r\n"
        b"\tfilemode = false\r\n"
        b"\tbare = false\r\n"
        b"\tlogallrefupdates = true\r\n"
        b"\tsymlinks = false\r\n"
        b"\tignorecase = true\r\n"
        b"\tautocrlf = input\r\n"
        b"\tsafecrlf = warn\r\n"
        b"[user]\r\n"
        b"\tname = Runtime Test\r\n"
        b"\temail = runtime@test.invalid\r\n"
    )
    parsed = _parse_local_git_config(config)
    _observe_local_repository_source(repository)
    completed = subprocess.run(
        ["git", "config", "--local", "--list", "--null"],
        cwd=repository,
        env=_hardened_git_environment(base=dict(os.environ)),
        check=True,
        capture_output=True,
    )
    oracle = []
    for record in completed.stdout.split(b"\x00"):
        if record:
            key, separator, value = record.partition(b"\n")
            assert separator == b"\n"
            oracle.append((key.decode("utf-8").casefold(), value.decode("utf-8")))
    assert [(entry.canonical_key, entry.value) for entry in parsed] == oracle


def test_global_git_config_is_ignored_and_sanitized_target_commit_is_inert(tmp_path: Path):
    repository = _repository(tmp_path / "source")
    source_before = _observe_local_repository_source(repository)
    profile = _profile(repository, profile_id="global-config-attack-v2")
    destination = tmp_path / "destination"
    destination.mkdir()
    built, identity = _materialize_local_repository_copy(
        profile=profile, destination_parent=destination, repository_name="work"
    )
    assert identity.initial_git_head == source_before.head
    owner_home = tmp_path / "owner-home"
    owner_home.mkdir()
    external_hooks = tmp_path / "owner-hooks"
    external_hooks.mkdir()
    sentinel = tmp_path / "owner-global-sentinel.txt"
    _sentinel_hook(external_hooks / "pre-commit", sentinel)
    command = _sentinel_command(tmp_path / "owner-command.cmd", sentinel)
    global_config = owner_home / ".gitconfig"
    global_config.write_text(
        "\n".join(
            (
                "[core]",
                f'\thooksPath = "{external_hooks.as_posix()}"',
                f'\tfsmonitor = "{command.as_posix()}"',
                "[commit]",
                "\tgpgSign = true",
                "[gpg]",
                f'\tprogram = "{command.as_posix()}"',
                "[attack]",
                "\tmarker = owner-global-config-was-read",
                "",
            )
        ),
        encoding="utf-8",
        newline="\n",
    )
    base_environment = dict(os.environ)
    base_environment.update(
        {
            "HOME": str(owner_home),
            "USERPROFILE": str(owner_home),
            "XDG_CONFIG_HOME": str(owner_home / "xdg"),
        }
    )
    environment = _hardened_git_environment(base=base_environment)
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"].casefold() == "nul"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_KEY_0"] == "core.fsmonitor"
    assert environment["GIT_CONFIG_VALUE_0"] == "false"

    def target_git(*arguments: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=built.repository,
            env=environment,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert completed.returncode == 0, completed.stderr
        return completed

    origins = target_git("config", "--show-origin", "--show-scope", "--list").stdout
    assert str(global_config) not in origins
    assert "owner-global-config-was-read" not in origins
    assert target_git("status", "--porcelain=v1", "--untracked-files=all").stdout == ""
    readme = built.repository / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "post-materialization commit\n",
        encoding="utf-8",
        newline="\n",
    )
    target_git("add", "README.md")
    target_git("commit", "--quiet", "-m", "test: sanitized target commit")
    assert target_git("status", "--porcelain=v1", "--untracked-files=all").stdout == ""
    assert target_git("remote").stdout == ""
    assert target_git("log", "-1", "--format=%an <%ae>").stdout.strip() == (
        "Admissible Native Mission <admissible-native@local.invalid>"
    )
    assert list((built.repository / ".git" / "hooks").iterdir()) == []
    assert not sentinel.exists()
    assert _observe_local_repository_source(repository) == source_before


def test_runtime_registered_fixture_source_preserves_registered_builder_path(tmp_path: Path):
    profile = create_native_mission_profile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
        profile_id="runtime-fixture-v2",
        run_id="runtime-fixture-v2-run",
        session_id="runtime-fixture-v2-run",
        gate_id="runtime-fixture-v2-gate",
        mission_id="runtime-fixture-v2-mission",
        mission_text="Add the configured deterministic fixture feature.",
        gate_objective="Complete the registered fixture mission.",
        gate_clauses=(("fixture.material", "The required fixture material changes."),),
        required_evidence_kinds=(EvidenceKind.TARGET_TREE.value, EvidenceKind.GIT_STATE.value),
        checkpoint_commands=(),
        completion_conditions_text="Complete the exact Git/material policy and stop.",
        budgets=(1, 1, 0, 0, 0),
        timeout_seconds=60,
        stdout_byte_limit=8192,
        stderr_byte_limit=8192,
        model="auto",
        workspace_source=WorkspaceSourceAuthority(
            kind=WorkspaceSourceKind.REGISTERED_FIXTURE,
            fixture_id="act-2a-canary-game-state",
            fixture_version=2,
        ),
        git_end_state_policy=GitEndStatePolicy(
            required_commits_added=1,
            required_complete_commit_message="feat: fixture runtime",
            final_worktree_clean=True,
            final_index_clean=True,
            final_remotes_absent=True,
            required_material_paths=("README.md",),
        ),
        verification=VerificationAuthority(
            mode=VerificationMode.OBSERVED_ONLY,
            verifier_source=None,
            verifier_source_sha256=None,
            verifier_timeout_seconds=None,
            verifier_output_limit_bytes=None,
            disclose_complete_source=False,
        ),
        runtime_prompt=RuntimePromptAuthority(
            permitted_effects=("Edit only the assigned fixture workspace.",),
            forbidden_effects=("Do not add remotes, push, deploy, or use network.",),
            stop_clause="Stop after the exact configured boundary passes.",
        ),
    )
    initialized = observe_initialized_workspace_identity(profile)
    root = tmp_path / profile.run_id
    root.mkdir()
    built = materialize_authorized_workspace(
        profile=profile,
        destination_parent=root,
        authorized_identity=initialized,
    )
    assert initialized.source_kind == WorkspaceSourceKind.REGISTERED_FIXTURE.value
    assert initialized.source_identity == profile.effective_workspace_source.identity_fingerprint
    assert _git(built.repository, "status", "--porcelain=v1", "--untracked-files=all").stdout == ""
    assert _git(built.repository, "remote").stdout.strip() == ""


def test_local_repository_preflight_rejects_untracked_in_progress_and_submodule(tmp_path: Path):
    untracked = _repository(tmp_path / "untracked")
    (untracked / "extra.txt").write_text("not authorized\n", encoding="utf-8")
    with pytest.raises(NativeEvidenceInvalid, match="clean|untracked"):
        _observe_local_repository_source(untracked)

    in_progress = _repository(tmp_path / "in-progress")
    (in_progress / ".git" / "MERGE_HEAD").write_text(
        _git(in_progress, "rev-parse", "HEAD").stdout.strip() + "\n", encoding="ascii"
    )
    with pytest.raises(NativeEvidenceInvalid, match="in-progress"):
        _observe_local_repository_source(in_progress)

    submodule = _repository(tmp_path / "submodule")
    head = _git(submodule, "rev-parse", "HEAD").stdout.strip()
    _git(submodule, "update-index", "--add", "--cacheinfo", f"160000,{head},deps/sub")
    _git(submodule, "commit", "--quiet", "-m", "test: add gitlink")
    with pytest.raises(NativeEvidenceInvalid, match="submodules|clean"):
        _observe_local_repository_source(submodule)


def test_scratch_rehearsal_is_removed_and_identity_mismatch_blocks_materialization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = _repository(tmp_path / "source")
    profile = _profile(repository)
    scratch = tmp_path / "controlled-scratch"
    monkeypatch.setattr(
        "admissible.delegated_gate.native_canary.tempfile.mkdtemp",
        lambda **_kwargs: str(scratch),
    )
    scratch.mkdir()
    identity = observe_initialized_workspace_identity(profile)
    assert not scratch.exists()
    run_root = tmp_path / "runtime-observed-v2-run"
    run_root.mkdir()
    mismatched = InitializedWorkspaceIdentity(
        initial_git_head="0" * 40,
        initial_material_tree_hash=identity.initial_material_tree_hash,
        initial_commit_count=identity.initial_commit_count,
        initial_commit_message=identity.initial_commit_message,
        source_kind=identity.source_kind,
        source_identity=identity.source_identity,
    ).validated()
    with pytest.raises(NativeEvidenceInvalid, match="authorized workspace identity"):
        materialize_authorized_workspace(
            profile=profile,
            destination_parent=run_root,
            authorized_identity=mismatched,
        )


def _runtime_mutation(repository: Path) -> None:
    readme = repository / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "runtime marker\n",
        encoding="utf-8",
        newline="\n",
    )
    _commit(repository, "feat: add runtime marker")


def _runtime_harness(
    tmp_path: Path,
    profile: NativeMissionProfile,
    *,
    mutation=_runtime_mutation,
) -> SimpleNamespace:
    source = Path(profile.effective_workspace_source.local_repository_path)
    document = tmp_path / "profile.json"
    document.write_bytes(canonical_bytes(profile.to_dict()) + b"\n")
    loaded = load_native_mission_profile_document(document.resolve())
    initialized = observe_initialized_workspace_identity(loaded)
    root = tmp_path / loaded.run_id
    root.mkdir()
    fixture = materialize_authorized_workspace(
        profile=loaded,
        destination_parent=root,
        authorized_identity=initialized,
    )
    evidence = root / "evidence"
    evidence.mkdir()
    config, attestor = _injected_test_cursor(tmp_path)
    attestation = attestor(config)
    payload = build_profile_authorization_payload(
        source_repository=source,
        source_head=_git(source, "rev-parse", "HEAD").stdout.strip(),
        attestation=attestation,
        run_root=root,
        profile=loaded,
        initialized_workspace=initialized,
    )
    _write_run_metadata_once(
        evidence / RUN_PREFLIGHT_METADATA_FILE_NAME,
        {
            "classification": "act-2a-native-delegated-executor-canary",
            "authorization_payload": payload.to_dict(),
            "attestation": attestation.to_dict(),
            "local_capability_status": "PREFLIGHT_READY",
            "durability_capability": {"ready": True},
        },
    )
    execution_store = AtomicNativeExecutionStore(evidence / "native-execution")
    session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
    session_store.create(create_canary_session(session_id=loaded.session_id, profile=loaded))
    runner = FakeNativeProcessRunner(mutation=mutation)
    executor = NativeDelegatedExecutor(
        config=config,
        process_runner=runner,
        clock=Clock(),
        local_attestor=attestor,
        harden_git_environment=True,
        git_metadata_inspector=_inspect_runtime_git_metadata,
    )
    coordinator = NativeCanaryCoordinator(
        session_store=session_store,
        execution_store=execution_store,
        executor=executor,
        backend_attestation=attestation,
        source_repository=source,
        work_workspace=fixture.repository,
        canary_parent=root,
        evidence_directory=evidence,
        timeout_seconds=loaded.timeout_seconds,
        stdout_byte_limit=loaded.stdout_byte_limit,
        stderr_byte_limit=loaded.stderr_byte_limit,
        profile=loaded,
    )
    if loaded.verification_mode is VerificationMode.OBSERVED_ONLY:
        with mock.patch(
            "admissible.delegated_gate.native_canary.run_behavioral_verifier",
            side_effect=AssertionError("observed-only must not execute a behavioral verifier"),
        ):
            outcome = coordinator.run(session_id=loaded.session_id)
    else:
        outcome = coordinator.run(session_id=loaded.session_id)
    _write_run_metadata_once(evidence / "final-status.json", outcome.to_dict())
    return SimpleNamespace(
        profile=loaded,
        source=source,
        root=root,
        evidence=evidence,
        session_store=session_store,
        execution_store=execution_store,
        runner=runner,
        outcome=outcome,
    )


@pytest.mark.parametrize(
    ("mode", "verdict"),
    [
        (VerificationMode.OBSERVED_ONLY, ProductVerdict.ADMITTED_OBSERVED.value),
        (VerificationMode.FROZEN_BEHAVIORAL, ProductVerdict.ADMITTED_VERIFIED.value),
    ],
)
def test_fake_end_to_end_document_path_reconstructs_truthful_admission(
    tmp_path: Path, mode: VerificationMode, verdict: str
):
    source = _repository(tmp_path / "source")
    before = _observe_local_repository_source(source)
    profile = _profile(
        source,
        mode=mode,
        profile_id=f"e2e-{mode.value.lower()}-v2",
        checkpoint_exit_code=0,
    )
    harness = _runtime_harness(tmp_path, profile)
    provider_environment = harness.runner.invocations[0].env
    assert provider_environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert provider_environment["GIT_CONFIG_GLOBAL"].casefold() == "nul"
    assert provider_environment["GIT_TERMINAL_PROMPT"] == "0"
    assert provider_environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert provider_environment["GIT_CONFIG_KEY_0"] == "core.fsmonitor"
    assert provider_environment["GIT_CONFIG_VALUE_0"] == "false"
    assert "ADMISSIBLE_NATIVE_CANARY_OWNER_AUTHORIZATION_SHA256" not in provider_environment
    assert harness.outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert harness.outcome.product_verdict == verdict
    assert harness.outcome.verification_mode == mode.value
    assert harness.outcome.checkpoint_status == "PASSED"
    assert harness.outcome.evidence_fingerprint == harness.outcome.checkpoint_fingerprint
    if mode is VerificationMode.OBSERVED_ONLY:
        assert harness.outcome.behavioral_non_claim == "Behavior was not independently verified."
        assert not harness.execution_store.has_behavioral_evidence(
            profile.session_id, profile.gate_id, 0
        )
    else:
        assert harness.outcome.behavioral_evidence_fingerprint is not None
        assert harness.outcome.verifier_source_sha256 == profile.verifier_source_sha256
        assert harness.outcome.behavioral_verifier_passed is True
    trap = mock.Mock(side_effect=AssertionError("registry lookup is forbidden"))
    with mock.patch("admissible.delegated_gate.native_canary.registered_profiles", trap):
        reconstructed = reconstruct_completed_native_mission(
            session_store=harness.session_store,
            execution_store=harness.execution_store,
            evidence_directory=harness.evidence,
            session_id=profile.session_id,
        )
    assert reconstructed.product_verdict == verdict
    assert reconstructed.to_dict() == harness.outcome.to_dict()
    assert _observe_local_repository_source(source) == before


def test_frozen_behavioral_failure_refuses_before_checkpoint(tmp_path: Path):
    source = _repository(tmp_path / "source")
    profile = _profile(
        source,
        mode=VerificationMode.FROZEN_BEHAVIORAL,
        profile_id="frozen-failure-v2",
        checkpoint_exit_code=0,
        frozen_source="process.exit(7);",
    )
    harness = _runtime_harness(tmp_path, profile)
    assert harness.outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    assert harness.outcome.product_verdict == ProductVerdict.REFUSED.value
    assert harness.outcome.exact_classification == NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED.value
    assert harness.outcome.failing_boundary == "pre_capture_eligibility"
    assert harness.outcome.evidence_fingerprint is not None
    assert not harness.execution_store.has_capture_attempt(profile.session_id, profile.gate_id, 0)
    assert not harness.session_store.load(profile.session_id).checkpoint_history
    assert reconstruct_completed_native_mission(
        session_store=harness.session_store,
        execution_store=harness.execution_store,
        evidence_directory=harness.evidence,
        session_id=profile.session_id,
    ).product_verdict == ProductVerdict.REFUSED.value


def test_checkpoint_failure_refuses_and_tampered_product_verdict_fails_closed(tmp_path: Path):
    source = _repository(tmp_path / "source")
    profile = _profile(
        source,
        profile_id="checkpoint-failure-v2",
        checkpoint_exit_code=9,
    )
    harness = _runtime_harness(tmp_path, profile)
    assert harness.outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURE_FAILED
    assert harness.outcome.product_verdict == ProductVerdict.REFUSED.value
    final_path = harness.evidence / "final-status.json"
    persisted = json.loads(final_path.read_text(encoding="utf-8"))
    persisted["product_verdict"] = ProductVerdict.ADMITTED_VERIFIED.value
    body = {key: value for key, value in persisted.items() if key != "product_outcome_fingerprint"}
    persisted["product_outcome_fingerprint"] = fingerprint(body)
    final_path.write_bytes(canonical_bytes(persisted) + b"\n")
    with pytest.raises(NativeEvidenceInvalid, match="product verdict"):
        reconstruct_completed_native_mission(
            session_store=harness.session_store,
            execution_store=harness.execution_store,
            evidence_directory=harness.evidence,
            session_id=profile.session_id,
        )


def test_execution_refuses_source_git_authority_mutation(tmp_path: Path):
    source = _repository(tmp_path / "source")
    profile = _profile(source, profile_id="source-authority-mutation-v2")

    def mutate_target_and_source(repository: Path) -> None:
        _runtime_mutation(repository)
        _git(source, "config", "runtime.tampered", "true")

    harness = _runtime_harness(tmp_path, profile, mutation=mutate_target_and_source)
    assert harness.outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    assert harness.outcome.product_verdict == ProductVerdict.REFUSED.value
    assert harness.outcome.failing_boundary == "executor_observation_failed"
    assert (
        harness.outcome.detail
        == "local Git configuration key is outside the source allowlist: runtime.tampered"
    )
    assert not harness.execution_store.has_execution_eligibility(
        profile.session_id, profile.gate_id, 0
    )


@pytest.mark.parametrize(
    ("failure_kind", "expected_reason"),
    [
        ("missing-material", "required_material_paths_missing"),
        ("dirty-worktree", "final_worktree_not_clean"),
        ("dirty-index", "final_worktree_not_clean"),
        ("remote", "git_remote_present"),
    ],
)
def test_runtime_git_policy_refuses_material_dirty_and_remote_failures(
    tmp_path: Path, failure_kind: str, expected_reason: str
):
    source = _repository(tmp_path / "source")
    profile = _profile(source, profile_id=f"policy-{failure_kind}-v2")

    def mutation(repository: Path) -> None:
        if failure_kind == "missing-material":
            (repository / "other.txt").write_text("other\n", encoding="utf-8")
            _commit(repository, "feat: add runtime marker")
            return
        _runtime_mutation(repository)
        if failure_kind in {"dirty-worktree", "dirty-index"}:
            readme = repository / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8") + "dirty\n", encoding="utf-8"
            )
            if failure_kind == "dirty-index":
                _git(repository, "add", "README.md")
        else:
            _git(
                repository,
                "remote",
                "add",
                "origin",
                (tmp_path / "not-contacted").as_posix(),
            )

    harness = _runtime_harness(tmp_path, profile, mutation=mutation)
    assert harness.outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    eligibility = harness.execution_store.load_execution_eligibility(
        profile.session_id, profile.gate_id, 0
    )
    assert expected_reason in eligibility.ineligibility_reasons


@pytest.mark.parametrize("tamper_kind", ["profile", "workspace_identity", "verification_mode"])
def test_runtime_reconstruction_rejects_tampered_persisted_authority(
    tmp_path: Path, tamper_kind: str
):
    source = _repository(tmp_path / "source")
    profile = _profile(source, profile_id=f"tamper-{tamper_kind}-v2")
    harness = _runtime_harness(tmp_path, profile)
    path = harness.evidence / RUN_PREFLIGHT_METADATA_FILE_NAME
    metadata = json.loads(path.read_text(encoding="utf-8"))
    payload = metadata["authorization_payload"]
    persisted_profile = payload["mission_profile"]
    if tamper_kind == "profile":
        persisted_profile["mission_text"] += " tampered"
        persisted_profile["profile_fingerprint"] = fingerprint(
            {key: value for key, value in persisted_profile.items() if key != "profile_fingerprint"}
        )
    elif tamper_kind == "workspace_identity":
        payload["initialized_workspace"]["initial_material_tree_hash"] = "0" * 64
    else:
        persisted_profile["verification"]["mode"] = VerificationMode.FROZEN_BEHAVIORAL.value
        persisted_profile["profile_fingerprint"] = fingerprint(
            {key: value for key, value in persisted_profile.items() if key != "profile_fingerprint"}
        )
    payload["payload_fingerprint"] = fingerprint(
        {key: value for key, value in payload.items() if key != "payload_fingerprint"}
    )
    path.write_bytes(canonical_bytes(metadata) + b"\n")
    with pytest.raises(NativeEvidenceInvalid):
        reconstruct_completed_native_mission(
            session_store=harness.session_store,
            execution_store=harness.execution_store,
            evidence_directory=harness.evidence,
            session_id=profile.session_id,
        )


def test_runtime_workspace_git_observations_receive_explicit_hardening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import admissible.delegated_gate.native_executor as native_executor_module

    source = _repository(tmp_path / "source")
    profile = _profile(source, profile_id="explicit-hardening-v2")
    recorded: list[tuple[Path, tuple[str, ...], bool | None]] = []
    production_git = native_executor_module._git

    def recording_git(repository, *arguments, timeout=30, harden_git=None):
        recorded.append((Path(repository).resolve(), tuple(arguments), harden_git))
        return production_git(repository, *arguments, timeout=timeout, harden_git=harden_git)

    monkeypatch.setattr(native_executor_module, "_git", recording_git)
    harness = _runtime_harness(tmp_path, profile)
    assert harness.outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS

    resolved_source = source.resolve()
    workspace_calls = [call for call in recorded if call[0] != resolved_source]
    assert workspace_calls
    workspaces = {call[0] for call in workspace_calls}
    assert len(workspaces) == 1
    workspace = workspaces.pop()
    assert workspace.is_relative_to(harness.root.resolve())

    explicit = [call for call in workspace_calls if call[2] is True]
    toplevel = [call for call in explicit if call[1][:2] == ("rev-parse", "--show-toplevel")]
    # Pre- and post-execution workspace observations both run rev-parse
    # --show-toplevel with the executor's explicit hardening decision.
    assert len(toplevel) >= 2
    assert any(call[1][:2] == ("rev-list", "--count") for call in explicit)
    assert any("--name-only" in call[1] and call[1][0] == "diff" for call in explicit)
    # No workspace Git subprocess may fall back to ambient configuration: every
    # call either carries the explicit runtime flag or resolves hardened via
    # the sanitized-workspace default.
    for _, arguments, harden_git in workspace_calls:
        assert harden_git is True or (
            harden_git is None
            and native_executor_module._is_sanitized_local_repository(workspace)
        ), arguments

    # Defense-in-depth recognizer: the genuine materialized sanitized target is
    # recognized; a normal repository is not.
    assert native_executor_module._is_sanitized_local_repository(workspace) is True
    assert native_executor_module._is_sanitized_local_repository(source) is False

    # Legacy registered-fixture executors keep harden_git_environment=False and
    # the wrapper's non-hardened dispatch stays on the ambient path.
    config, attestor = _injected_test_cursor(tmp_path / "legacy-backend")
    legacy = NativeDelegatedExecutor(
        config=config,
        process_runner=FakeNativeProcessRunner(mutation=_runtime_mutation),
        clock=Clock(),
        local_attestor=attestor,
    )
    assert legacy.harden_git_environment is False
    hardened_trap = mock.Mock(side_effect=AssertionError("ambient path must not harden"))
    with mock.patch.object(native_executor_module, "_hardened_git_environment", hardened_trap):
        ambient = production_git(source, "rev-parse", "HEAD", harden_git=False)
    assert ambient.returncode == 0
    hardened_trap.assert_not_called()
