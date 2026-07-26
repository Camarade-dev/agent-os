"""Step 5C2E3: installed, provider-free historical-pairing operator acceptance.

Every product process exercised here is a real child process started from one
isolated external installation of a wheel built outside this repository.  The
acceptance harness never reaches into the product in-process: it starts the
installed ``admissible`` launcher, speaks the real loopback HTTP surface, runs
the two installed operator console scripts, and reads the configured archive
from the filesystem.  Repository imports appear only as independent oracles for
expectations, never as the thing under test.

Real, provider-free wrapper acquisition
---------------------------------------

The historical V4 wrapper is produced by the repository's own preflight-only
serializer -- the exact ``admissible.product_launcher.preflight_runner`` child
the product itself spawns -- run with ``--attestation-class wrapper-chain``.
That class performs static local discovery and parse attestation only: it never
executes the launcher bundle, never contacts a provider, never starts a task,
creates no run root, and produces no result, evidence record, or acceptance
claim.  The mission profile the wrapper authorizes is itself authored by the
real installed product through its own ``POST /ui/api/v1/contracts`` route, so
nothing about the wrapper family is hand-approximated here.

What acceptance here does and does not mean
-------------------------------------------

Publishing the three canonical archive documents means only that a valid
deterministic tag for one exact pairing authority was presented and that the
complete archive is loadable.  It is not proof that an execution occurred, that
a claim is supported, that evidence exists, or that the asserted actor is who
they say they are.  The derived V5 stays non-launchable, the tag stays a
symmetric shared-secret code rather than a signature, ``actor_id`` stays
asserted, and the archive stays free of any confirmation receipt.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection
from types import SimpleNamespace

import pytest

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.historical_evaluation import (
    project_v5_runtime_authority_to_v2,
)
from admissible.delegated_gate.historical_evaluation_store import (
    AUTHORITY_DIRECTORY_NAME,
    AUTHORITY_FILE_SUFFIX,
    PAYLOAD_DIRECTORY_NAME,
    PAYLOAD_FILE_SUFFIX,
    PROFILE_DIRECTORY_NAME,
    PROFILE_FILE_SUFFIX,
    load_historical_evaluation_pairing,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN,
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR,
    MAX_CONFIRMATION_SECRET_BYTES,
    MIN_CONFIRMATION_SECRET_BYTES,
    build_historical_pairing_confirmation_message,
    compute_historical_pairing_confirmation_tag,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    load_historical_native_canary_authorization_payload_v4,
)
from admissible.product_launcher.historical_pairing_enablement import (
    HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
)
from admissible.product_launcher.historical_pairing_registry import (
    MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_PATH = REPO_ROOT / "docs" / "runbooks" / "historical_pairing_operator.md"

# Every production file whose exported byte identity is proven before the
# distribution is built.  A drift here means the isolated installation would not
# be the committed product.
COMMITTED_PRODUCTION_PATHS = (
    "pyproject.toml",
    "admissible/product_launcher/__main__.py",
    "admissible/operator_tools/historical_pairing_v4_extract.py",
    "admissible/operator_tools/historical_pairing_tag.py",
    "admissible/historical_pairing_secret_file.py",
    "admissible/product_launcher/historical_pairing_registry.py",
    "admissible/delegated_gate/historical_pairing_workflow.py",
    "admissible/delegated_gate/historical_pairing_confirmation.py",
    "admissible/product_launcher/launcher.py",
    "admissible/product_launcher/ui_transport.py",
    "admissible/product_launcher/historical_pairing_service.py",
    "admissible/product_launcher/historical_pairing_enablement.py",
    "admissible/product_launcher/preflight_runner.py",
    "admissible/delegated_gate/historical_evaluation_store.py",
    "admissible/delegated_gate/historical_evaluation.py",
    "admissible/delegated_gate/historical_pairing_review.py",
    "admissible/delegated_gate/native_canary.py",
)

INSTALLED_CONSOLE_SCRIPTS = {
    "agent-os": "agent_os.cli:main",
    "admissible": "admissible.product_launcher.__main__:main",
    "admissible-historical-pairing-tag": (
        "admissible.operator_tools.historical_pairing_tag:main"
    ),
    "admissible-historical-pairing-v4-extract": (
        "admissible.operator_tools.historical_pairing_v4_extract:main"
    ),
}

ISOLATED_IMPORT_ORIGINS = (
    "admissible",
    "admissible.product_launcher",
    "admissible.operator_tools.historical_pairing_v4_extract",
    "admissible.operator_tools.historical_pairing_tag",
    "admissible.historical_pairing_secret_file",
)

UI_PREFIX = "/ui/api/v1"
HISTORICAL_ROOT = UI_PREFIX + "/historical-pairings"
PAYLOADS_ROUTE = HISTORICAL_ROOT + "/payloads"
PREPARATIONS_ROUTE = HISTORICAL_ROOT + "/preparations"
CONFIRMATION_HEADER = "X-Admissible-Historical-Pairing-Confirmation"
CSRF_HEADER = "X-Admissible-UI-CSRF"

SUCCESS_LINE = b"status=STANDALONE_V4_WRITTEN" + os.linesep.encode("ascii")
PAYLOAD_ID = "acceptance-historical-001"
ACTOR_ID = "operator.acceptance"
CHECKPOINT_COMMAND_ID = "workspace-marker-check"
READINESS_PATTERN = re.compile(r"^ui=http://127\.0\.0\.1:(\d+)/ g2_port=(\d+)$")

# One exact-byte binary secret containing a NUL, a high byte, CR, LF and a
# space, so a text writer, a newline fixer, or an encoding round trip could not
# reproduce it.
SECRET_BYTES = (
    b"\x00\xff\r\n admissible-historical-pairing-acceptance\x80\x7f\t"
)

READINESS_TIMEOUT_SECONDS = 90.0
HTTP_TIMEOUT_SECONDS = 30.0
# Windows loopback occasionally resets a freshly accepted connection. Exactly
# this bounded retry is permitted, and it is never used to mask a real refusal:
# a retried attempt that produces an HTTP status is reported unchanged.
LOOPBACK_RETRIES = 3


# ---------------------------------------------------------------------------
# Bounded process and transport helpers.
# ---------------------------------------------------------------------------


# Every child argv and every explicit environment overlay this module ever
# passes to a child process, recorded so the confidentiality assertions can be
# made over the real spawn inputs rather than over the parent's environment.
SPAWNED_ARGV: list[list[str]] = []
SPAWNED_ENVIRONMENT_OVERLAYS: list[dict] = []


def _run(argv, *, cwd=None, env=None, timeout=300):
    """Run one bounded child and capture raw bytes on both streams."""

    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        environment.update(env)
    SPAWNED_ARGV.append([str(item) for item in argv])
    SPAWNED_ENVIRONMENT_OVERLAYS.append(dict(env or {}))
    return subprocess.run(
        [str(item) for item in argv],
        cwd=None if cwd is None else str(cwd),
        env=environment,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _git(repository: Path, *arguments: str) -> str:
    completed = _run(["git", "-C", str(repository), *arguments])
    assert completed.returncode == 0, completed.stderr[-400:]
    return completed.stdout.decode("utf-8", "replace")


def _free_of(blob: bytes, needle: bytes) -> bool:
    return needle not in blob


class InstalledStartupRefused(RuntimeError):
    """The installed launcher child never printed its readiness line.

    This is a real observation about the product under test, not a harness
    defect, so it is recorded and asserted by the acceptance tests rather than
    being allowed to abort collection or setup.
    """

    def __init__(self, *, readiness: str, stdout: bytes, stderr: bytes) -> None:
        super().__init__("installed launcher did not reach readiness")
        self.readiness = readiness
        self.stdout = stdout
        self.stderr = stderr


class InstalledLauncher:
    """One real installed launcher child bound to loopback only."""

    def __init__(self, scripts: Path, arguments, *, cwd: Path):
        self.argv = [str(scripts / "admissible.exe")] + [
            str(item) for item in arguments
        ]
        if not Path(self.argv[0]).exists():
            self.argv[0] = str(scripts / "admissible")
        self._cwd = cwd
        self.process: subprocess.Popen | None = None
        self.ui_port: int | None = None
        self.g2_port: int | None = None
        self.readiness_line = ""
        self.stdout_bytes = b""
        self.stderr_bytes = b""

    def __enter__(self) -> "InstalledLauncher":
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        SPAWNED_ARGV.append(list(self.argv))
        SPAWNED_ENVIRONMENT_OVERLAYS.append({"PYTHONDONTWRITEBYTECODE": "1"})
        self.process = subprocess.Popen(
            self.argv,
            cwd=str(self._cwd),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
        line = b""
        while time.monotonic() < deadline:
            line = self.process.stdout.readline()
            if line:
                break
            if self.process.poll() is not None:
                break
        self.readiness_line = line.decode("utf-8", "replace").strip()
        match = READINESS_PATTERN.match(self.readiness_line)
        if match is None:
            self.close()
            raise InstalledStartupRefused(
                readiness=self.readiness_line,
                stdout=self.stdout_bytes,
                stderr=self.stderr_bytes,
            )
        self.ui_port = int(match.group(1))
        self.g2_port = int(match.group(2))
        return self

    def __exit__(self, *_exception) -> None:
        self.close()

    def close(self) -> None:
        process = self.process
        if process is None:
            return
        self.process = None
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()
                process.wait(timeout=30)
        remaining_out, remaining_err = process.communicate(timeout=30)
        self.stdout_bytes += remaining_out or b""
        self.stderr_bytes += remaining_err or b""

    # -- transport ------------------------------------------------------

    def call(self, method: str, path: str, *, body=None, extra=None):
        assert self.ui_port is not None
        headers = {"Host": f"127.0.0.1:{self.ui_port}"}
        data = None
        if body is not None:
            data = json.dumps(
                body, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(data))
        if extra:
            headers.update(extra)
        last: OSError | None = None
        for _attempt in range(LOOPBACK_RETRIES):
            connection = HTTPConnection(
                "127.0.0.1", self.ui_port, timeout=HTTP_TIMEOUT_SECONDS
            )
            try:
                connection.request(method, path, body=data, headers=headers)
                response = connection.getresponse()
                raw = response.read()
                content_type = response.headers.get("Content-Type", "")
                parsed: object | None = {}
                if raw:
                    if content_type.startswith("application/json"):
                        parsed = json.loads(raw.decode("utf-8"))
                    else:
                        # Assets are returned verbatim; nothing is parsed.
                        parsed = None
                return response.status, parsed, raw
            except (ConnectionResetError, socket.error) as failure:
                last = failure
            finally:
                connection.close()
        raise AssertionError(f"loopback transport failed: {last!r}")

    def json_call(self, method: str, path: str, *, body=None, extra=None):
        status, parsed, _raw = self.call(method, path, body=body, extra=extra)
        return status, parsed

    def csrf(self) -> str:
        status, boot = self.json_call("GET", UI_PREFIX + "/bootstrap")
        assert status == 200
        return boot["csrf_nonce"]


# ---------------------------------------------------------------------------
# Deterministic owner-authored evaluation material.
# ---------------------------------------------------------------------------


def _owner_material(actor_suffix: str) -> dict:
    """One complete owner authoring request, deterministic per actor suffix.

    A non-empty suffix also changes owner claim content, not just the asserted
    actor, so an independent control preparation derives a *different* V5
    evaluation profile as well as a different pairing authority.  The profile
    fingerprint covers the owner-authored evaluation layers and not ``actor_id``,
    so varying the actor alone would leave the profile document identical.
    """

    material = {
        "payload_id": PAYLOAD_ID,
        "actor_id": ACTOR_ID + actor_suffix,
        "result_claims": [
            {
                "claim_id": "claim.marker",
                "statement": (
                    "The recorded workspace material carries the acceptance "
                    "marker file at its authorized relative path."
                ),
                "obligation_level": "MANDATORY",
                "depends_on": [],
                "non_claims": [
                    "Does not assert that the marker content is correct.",
                    "Does not assert that any execution occurred.",
                ],
            },
            {
                "claim_id": "claim.commit",
                "statement": (
                    "Exactly one local commit carrying the required complete "
                    "message is present in the recorded material."
                ),
                "obligation_level": "ADVISORY",
                "depends_on": ["claim.marker"],
                "non_claims": ["Does not adjudicate commit authorship."],
            },
        ],
        "claim_verification_plan": [
            {
                "obligation_id": "verify.marker",
                "claim_ids": ["claim.marker"],
                "strategy": "CHECKPOINT_COMMAND",
                "procedure_reference": CHECKPOINT_COMMAND_ID,
                "acceptance_predicate": "EXIT_CODE_ZERO",
                "declared_coverage": (
                    "Exercises exactly one bounded slice of the recorded "
                    "workspace material."
                ),
                "non_claims": [
                    "Does not adjudicate the claim.",
                    "Does not establish that the obligation was satisfied.",
                ],
                "oracle_disclosed_to_subject": False,
                "independence_requirements": {
                    "temporal": True,
                    "artifact": True,
                    "process": True,
                    "information": False,
                    "model": True,
                    "organizational": True,
                },
                "negative_controls": [
                    {
                        "control_id": "negative.marker-absent",
                        "description": (
                            "A recorded tree without the marker file must not "
                            "satisfy this obligation."
                        ),
                    }
                ],
                "reference_cases": ["case.marker-present"],
            },
            {
                "obligation_id": "verify.commit",
                "claim_ids": ["claim.commit"],
                "strategy": "HUMAN_RUBRIC_OBSERVATION",
                "procedure_reference": "rubric.commit-shape",
                "acceptance_predicate": "HUMAN_RUBRIC_PASS",
                "declared_coverage": (
                    "A human reader inspects the recorded commit shape only."
                ),
                "non_claims": ["Does not adjudicate the claim."],
                "oracle_disclosed_to_subject": False,
                "independence_requirements": {
                    "temporal": True,
                    "artifact": True,
                    "process": True,
                    "information": True,
                    "model": True,
                    "organizational": False,
                },
                "negative_controls": [
                    {
                        "control_id": "negative.commit-absent",
                        "description": (
                            "A recorded history with no new commit must not "
                            "satisfy this obligation."
                        ),
                    }
                ],
                "reference_cases": ["case.single-commit"],
            },
        ],
        "verification_evidence_bindings": [
            {
                "binding_id": "binding.marker",
                "obligation_id": "verify.marker",
                "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
                "source_authority_reference": CHECKPOINT_COMMAND_ID,
            }
        ],
    }
    if actor_suffix:
        material["result_claims"][0]["non_claims"].append(
            "Independent control preparation" + actor_suffix + "."
        )
    return material


# ---------------------------------------------------------------------------
# Session fixture: the complete installed operator workflow, executed once.
# ---------------------------------------------------------------------------


def _require_external_root(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("e2e")
    resolved = Path(os.path.abspath(os.fspath(root)))
    assert REPO_ROOT not in resolved.parents and resolved != REPO_ROOT
    return resolved


def _build_isolated_installation(base: Path) -> SimpleNamespace:
    """Export, build and install the committed product outside the repository."""

    export = base / "src"
    export.mkdir()
    archived = _run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.eol=lf",
            "archive",
            "--format=tar",
            "HEAD",
        ]
    )
    assert archived.returncode == 0, archived.stderr[-400:]
    tar_path = base / "export.tar"
    tar_path.write_bytes(archived.stdout)
    extracted = _run(["tar", "-xf", str(tar_path), "-C", str(export)])
    assert extracted.returncode == 0, extracted.stderr[-400:]

    export_identity = {}
    for relative in COMMITTED_PRODUCTION_PATHS:
        committed = _run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", f"HEAD:{relative}"]
        )
        assert committed.returncode == 0, relative
        exported = _run(["git", "hash-object", "--", str(export / relative)])
        assert exported.returncode == 0, relative
        export_identity[relative] = (
            committed.stdout.decode("ascii").strip(),
            exported.stdout.decode("ascii").strip(),
        )

    dist = base / "dist"
    built = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(dist),
            ".",
        ],
        cwd=export,
        timeout=900,
    )
    assert built.returncode == 0, built.stdout[-2000:] + built.stderr[-2000:]
    wheels = sorted(dist.glob("agent_os-*.whl"))
    assert len(wheels) == 1, wheels

    venv = base / "venv"
    created = _run([sys.executable, "-m", "venv", str(venv)], timeout=900)
    assert created.returncode == 0, created.stderr[-2000:]
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    installed = _run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            str(wheels[0]),
        ],
        timeout=900,
    )
    assert installed.returncode == 0, installed.stderr[-2000:]

    origins = _run(
        [
            str(python),
            "-c",
            (
                "import importlib,json,sys\n"
                "print(json.dumps({m: getattr(importlib.import_module(m),"
                " '__file__', '') for m in "
                + repr(list(ISOLATED_IMPORT_ORIGINS))
                + "}))"
            ),
        ],
        cwd=base,
    )
    # The probe result is recorded, never asserted here: whether the product
    # really imports from the isolated installation is an acceptance claim and
    # belongs to a test, not to fixture setup.
    try:
        import_origins = json.loads(origins.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        import_origins = {}

    return SimpleNamespace(
        export=export,
        export_identity=export_identity,
        wheel=wheels[0],
        wheel_sha256=hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
        venv=venv,
        scripts=scripts,
        python=python,
        import_origins=import_origins,
        origins_probe=origins,
    )


def _external_source_repository(base: Path) -> SimpleNamespace:
    """One clean, remote-free external Git repository with a stable HEAD."""

    source = base / "srcrepo"
    (source / "app").mkdir(parents=True)
    (source / "app" / "main.js").write_bytes(
        b'console.log("historical pairing acceptance material");\n'
    )
    (source / "README.md").write_bytes(
        b"# acceptance-source\n\nStatic material for one historical pairing "
        b"acceptance rehearsal.\n"
    )
    assert _run(["git", "init", "-q", "-b", "main", str(source)]).returncode == 0
    for name, value in (
        ("user.name", "Acceptance Operator"),
        ("user.email", "operator@example.invalid"),
        ("commit.gpgsign", "false"),
        # Pinned locally so a host-wide CRLF policy cannot make the exported
        # worktree look dirty to the product's own hardened Git observation.
        ("core.autocrlf", "false"),
    ):
        _git(source, "config", name, value)
    _git(source, "add", "-A")
    stamped = {
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    }
    committed = _run(
        ["git", "-C", str(source), "commit", "-q", "-m", "acceptance source material"],
        env=stamped,
    )
    assert committed.returncode == 0, committed.stderr[-400:]
    head = _git(source, "rev-parse", "HEAD").strip().lower()
    status = _git(source, "status", "--porcelain=v1", "--untracked-files=all")
    remotes = _git(source, "remote", "-v")
    return SimpleNamespace(path=source, head=head, status=status, remotes=remotes)


def _author_real_contract(installation, source, base: Path) -> SimpleNamespace:
    """Author one real runtime-V2 contract document through the product route."""

    runtime = base / "rt0"
    runtime.mkdir()
    arguments = [
        "--source-repository", str(source.path),
        "--required-source-head", source.head,
        "--run-parent", str(runtime / "runs"),
        "--contract-documents-directory", str(runtime / "contracts"),
        "--executable", "cursor-agent",
        "--attestation-class", "wrapper-chain",
        "--ui-port", "0",
        "--g2-port", "0",
        "--no-browser",
    ]
    with InstalledLauncher(installation.scripts, arguments, cwd=runtime) as launcher:
        csrf = launcher.csrf()
        status, authored = launcher.json_call(
            "POST",
            UI_PREFIX + "/contracts",
            body={
                "template_id": "observed-local-git-v1",
                "mission_text": (
                    "Record one bounded static marker inside the assigned "
                    "workspace copy of the acceptance source material. No "
                    "network access is permitted."
                ),
                "gate_objective": (
                    "Produce exactly one local commit carrying the required "
                    "marker."
                ),
                "completion_conditions_text": (
                    "The workspace contains app/main.js and README.md, exactly "
                    "one new local commit exists, the worktree and index are "
                    "clean, and no remote is configured."
                ),
                "commit_message": "chore: record acceptance marker",
                "required_material_paths": ["app/main.js", "README.md"],
            },
            extra={CSRF_HEADER: csrf},
        )
    assert status == 200, authored
    assert (
        authored["contract_summary"]["schema_version"]
        == MISSION_PROFILE_SCHEMA_VERSION_V2
    )
    documents = sorted((runtime / "contracts").glob("contract-*.json"))
    assert len(documents) == 1, documents
    return SimpleNamespace(
        document=documents[0],
        summary=authored["contract_summary"],
        generated=authored["generated_ids"],
        runtime=runtime,
    )


def _acquire_real_wrapper(installation, source, contract, base: Path):
    """Run the product's own preflight-only child and keep its exact envelope."""

    runs = base / "wrapper-runs"
    runs.mkdir()
    run_root = runs / contract.generated["run_id"]
    completed = _run(
        [
            str(installation.python),
            "-m",
            "admissible.product_launcher.preflight_runner",
            "--source-repository", str(source.path),
            "--required-source-head", source.head,
            "--run-root", str(run_root),
            "--run-id", contract.generated["run_id"],
            "--session-id", contract.generated["session_id"],
            "--executable", "cursor-agent",
            "--profile-document", str(contract.document),
            "--attestation-class", "wrapper-chain",
        ],
        cwd=base,
        timeout=900,
    )
    wrapper = base / "wrapper.json"
    wrapper.write_bytes(completed.stdout)
    return SimpleNamespace(
        path=wrapper,
        returncode=completed.returncode,
        run_root=run_root,
        stdout=completed.stdout,
    )


@pytest.fixture(scope="session")
def workflow(tmp_path_factory):
    """Execute the complete installed operator workflow exactly once."""

    if os.name != "nt":  # pragma: no cover - platform-honest skip
        pytest.skip("the installed operator runbook targets a Windows operator")
    for tool in ("git", "tar"):
        if shutil.which(tool) is None:  # pragma: no cover - environment honest
            pytest.skip(f"{tool} is required to build the faithful export")

    base = _require_external_root(tmp_path_factory)
    installation = _build_isolated_installation(base)
    source = _external_source_repository(base)
    contract = _author_real_contract(installation, source, base)
    wrapper = _acquire_real_wrapper(installation, source, contract, base)
    if wrapper.returncode != 0:  # pragma: no cover - environment honest
        pytest.skip(
            "the local backend could not be attested provider-free, so no real "
            "preflight-only wrapper could be produced on this host"
        )

    # -- E. installed standalone-V4 extraction ---------------------------
    standalone = base / "standalone-v4.json"
    extracted = _run(
        [
            str(installation.scripts / "admissible-historical-pairing-v4-extract"),
            "--wrapper-file", str(wrapper.path),
            "--output-file", str(standalone),
        ],
        cwd=base,
    )
    standalone_bytes = standalone.read_bytes() if standalone.exists() else b""

    # Re-running against the same output path must refuse rather than overwrite.
    not_overwritten = _run(
        [
            str(installation.scripts / "admissible-historical-pairing-v4-extract"),
            "--wrapper-file", str(wrapper.path),
            "--output-file", str(standalone),
        ],
        cwd=base,
    )

    # A wrapper whose sibling status says FAILED still yields the same payload.
    envelope = json.loads(wrapper.path.read_bytes().decode("utf-8"))
    failed_envelope = dict(envelope)
    failed_envelope["status"] = "PREFLIGHT_BLOCKED"
    failed_wrapper = base / "wrapper-failed.json"
    failed_wrapper.write_bytes(
        json.dumps(failed_envelope, sort_keys=True).encode("utf-8")
    )
    failed_output = base / "standalone-from-failed.json"
    failed_extract = _run(
        [
            str(installation.scripts / "admissible-historical-pairing-v4-extract"),
            "--wrapper-file", str(failed_wrapper),
            "--output-file", str(failed_output),
        ],
        cwd=base,
    )

    # A malformed wrapper must never create the configured output.
    malformed_wrapper = base / "wrapper-malformed.json"
    malformed_wrapper.write_bytes(wrapper.path.read_bytes()[:512])
    malformed_output = base / "standalone-from-malformed.json"
    malformed_extract = _run(
        [
            str(installation.scripts / "admissible-historical-pairing-v4-extract"),
            "--wrapper-file", str(malformed_wrapper),
            "--output-file", str(malformed_output),
        ],
        cwd=base,
    )

    # An audited extraction proves the tool never reads a wrapper sibling.
    audit = _audited_extraction(installation, base, envelope)

    # -- F. exact secret and enablement configuration --------------------
    secret_file = base / "secret.bin"
    with open(secret_file, "wb") as handle:
        handle.write(SECRET_BYTES)
    archive_root = base / "archive"
    config_file = base / "historical-pairing.json"
    enablement = {
        "schema_version": HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
        "archive_root": str(archive_root),
        "payloads": [
            {"payload_id": PAYLOAD_ID, "document_path": str(standalone)}
        ],
        "preparation_ttl_seconds": 900,
        "max_preparations": 16,
    }
    config_bytes = json.dumps(enablement, indent=1, sort_keys=True).encode("utf-8")
    with open(config_file, "wb") as handle:
        handle.write(config_bytes)

    # -- disabled and partially configured installed smokes ---------------
    disabled = _disabled_feature_smoke(installation, source, base)
    partial = _partial_configuration_smoke(
        installation, source, base, config_file
    )

    # -- G through L: the enabled operator session ------------------------
    session = _enabled_session(
        installation,
        source,
        base,
        config_file=config_file,
        secret_file=secret_file,
        archive_root=archive_root,
        runtime_name="rt1",
    )

    # -- M. restart semantics ---------------------------------------------
    restart = _restart_session(
        installation,
        source,
        base,
        config_file=config_file,
        secret_file=secret_file,
        archive_root=archive_root,
        first=session,
    )

    return SimpleNamespace(
        base=base,
        installation=installation,
        source=source,
        contract=contract,
        wrapper=wrapper,
        standalone=standalone,
        standalone_bytes=standalone_bytes,
        extracted=extracted,
        not_overwritten=not_overwritten,
        failed_extract=failed_extract,
        failed_output=failed_output,
        malformed_extract=malformed_extract,
        malformed_output=malformed_output,
        audit=audit,
        secret_file=secret_file,
        config_file=config_file,
        config_bytes=config_bytes,
        archive_root=archive_root,
        disabled=disabled,
        partial=partial,
        session=session,
        restart=restart,
    )


def _audited_extraction(installation, base: Path, envelope: dict) -> SimpleNamespace:
    """Extract once under an audit hook that records every touched path."""

    isolated = base / "audited"
    isolated.mkdir()
    wrapper = isolated / "canary-preflight.json"
    wrapper.write_bytes(json.dumps(envelope, sort_keys=True).encode("utf-8"))
    # Deliberate neighbours: an evidence sibling and a second wrapper family.
    (isolated / "native-execution.json").write_bytes(b'{"sibling":"never-read"}')
    (isolated / "behavioral-evidence.json").write_bytes(b'{"sibling":"never-read"}')
    (isolated / "notes.txt").write_bytes(b"never-read")

    guard = base / "auditguard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        "import atexit, os, sys\n"
        "_prefix = os.environ.get('ADMISSIBLE_AUDIT_PREFIX', '')\n"
        "_log = os.environ.get('ADMISSIBLE_AUDIT_LOG', '')\n"
        "_events = []\n"
        "_state = {'recording': True}\n"
        "def _hook(event, args):\n"
        "    if not _state['recording'] or not _prefix:\n"
        "        return\n"
        "    if event not in ('open', 'os.listdir', 'os.scandir', 'os.stat'):\n"
        "        return\n"
        "    try:\n"
        "        target = args[0]\n"
        "        text = target if isinstance(target, str) else os.fsdecode(target)\n"
        "    except Exception:\n"
        "        return\n"
        "    if text.lower().startswith(_prefix.lower()):\n"
        "        _events.append(event + '|' + text)\n"
        "sys.addaudithook(_hook)\n"
        "def _flush():\n"
        "    _state['recording'] = False\n"
        "    if _log:\n"
        "        with open(_log, 'w', encoding='utf-8') as handle:\n"
        "            handle.write('\\n'.join(_events))\n"
        "atexit.register(_flush)\n",
        encoding="utf-8",
    )
    log = base / "audit-events.txt"
    output = base / "standalone-audited.json"
    completed = _run(
        [
            str(installation.python),
            "-m",
            "admissible.operator_tools.historical_pairing_v4_extract",
            "--wrapper-file", str(wrapper),
            "--output-file", str(output),
        ],
        cwd=base,
        env={
            "PYTHONPATH": str(guard),
            "ADMISSIBLE_AUDIT_PREFIX": str(isolated),
            "ADMISSIBLE_AUDIT_LOG": str(log),
        },
    )
    events = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return SimpleNamespace(
        directory=isolated,
        wrapper=wrapper,
        output=output,
        completed=completed,
        events=[line for line in events if line],
    )


def _disabled_feature_smoke(installation, source, base: Path) -> SimpleNamespace:
    runtime = base / "rt-disabled"
    runtime.mkdir()
    arguments = [
        "--source-repository", str(source.path),
        "--required-source-head", source.head,
        "--run-parent", str(runtime / "runs"),
        "--contract-documents-directory", str(runtime / "contracts"),
        "--executable", "cursor-agent",
        "--attestation-class", "wrapper-chain",
        "--ui-port", "0", "--g2-port", "0", "--no-browser",
    ]
    observed = {}
    with InstalledLauncher(installation.scripts, arguments, cwd=runtime) as launcher:
        csrf = launcher.csrf()
        observed["payloads"] = launcher.json_call("GET", PAYLOADS_ROUTE)
        observed["review"] = launcher.json_call(
            "GET", PREPARATIONS_ROUTE + "/whatever/" + "0" * 64
        )
        observed["unknown_get"] = launcher.json_call(
            "GET", UI_PREFIX + "/no-such-collection"
        )
        observed["prepare"] = launcher.json_call(
            "POST",
            PREPARATIONS_ROUTE,
            body=_owner_material(".disabled"),
            extra={CSRF_HEADER: csrf},
        )
        observed["unknown_post"] = launcher.json_call(
            "POST",
            UI_PREFIX + "/no-such-collection",
            body={},
            extra={CSRF_HEADER: csrf},
        )
        observed["confirm"] = launcher.json_call(
            "POST",
            PREPARATIONS_ROUTE + "/whatever/confirmation",
            body={"expected_authority_fingerprint": "0" * 64},
            extra={CSRF_HEADER: csrf, CONFIRMATION_HEADER: "a" * 64},
        )
    return SimpleNamespace(observed=observed, runtime=runtime)


def _partial_configuration_smoke(
    installation, source, base: Path, config_file: Path
) -> SimpleNamespace:
    runtime = base / "rt-partial"
    results = {}
    for label, extra in (
        ("config_only", ["--historical-pairing-config", str(config_file)]),
        (
            "secret_only",
            ["--historical-pairing-secret-file", str(base / "secret.bin")],
        ),
    ):
        target = runtime / label
        completed = _run(
            [
                str(installation.scripts / "admissible"),
                "--source-repository", str(source.path),
                "--required-source-head", source.head,
                "--run-parent", str(target / "runs"),
                "--contract-documents-directory", str(target / "contracts"),
                "--executable", "cursor-agent",
                "--attestation-class", "wrapper-chain",
                "--ui-port", "0", "--g2-port", "0", "--no-browser",
                *extra,
            ],
            cwd=base,
            timeout=180,
        )
        results[label] = SimpleNamespace(
            completed=completed,
            runtime_created=target.exists(),
        )
    return SimpleNamespace(results=results, runtime=runtime)


def _prepare_and_export(launcher, base: Path, suffix: str, *, index: int):
    """Prepare one pairing and export its exact public confirmation message."""

    csrf = launcher.csrf()
    status, prepared = launcher.json_call(
        "POST",
        PREPARATIONS_ROUTE,
        body=_owner_material(suffix),
        extra={CSRF_HEADER: csrf},
    )
    assert status == 201, prepared
    identity = prepared["pairing_identity"]
    preparation_id = identity["preparation_id"]
    authority_fingerprint = identity["pairing_authority_fingerprint"]
    review_status, review = launcher.json_call(
        "GET",
        f"{PREPARATIONS_ROUTE}/{preparation_id}/{authority_fingerprint}",
    )
    assert review_status == 200, review
    message = base64.b64decode(
        review["pairing_identity"]["confirmation_message_base64"], validate=True
    )
    message_file = base / f"confirmation-message-{index}.bin"
    with open(message_file, "wb") as handle:
        handle.write(message)
    return SimpleNamespace(
        csrf=csrf,
        prepared=prepared,
        identity=identity,
        review=review,
        preparation_id=preparation_id,
        authority_fingerprint=authority_fingerprint,
        message=message,
        message_file=message_file,
    )


def _installed_tag(installation, message_file: Path, secret_file: Path):
    return _run(
        [
            str(installation.scripts / "admissible-historical-pairing-tag"),
            "--message-file", str(message_file),
            "--secret-file", str(secret_file),
        ],
        cwd=installation.venv,
    )


def _archive_inventory(archive_root: Path):
    if not archive_root.exists():
        return []
    return sorted(
        path.relative_to(archive_root).as_posix()
        for path in archive_root.rglob("*")
        if path.is_file()
    )


def _refused_enabled_session(runtime: Path, refused) -> SimpleNamespace:
    """Record a refused enabled startup without inventing any workflow result."""

    return SimpleNamespace(
        runtime=runtime,
        readiness=refused.readiness,
        startup_refusal=refused,
        stdout=refused.stdout,
        stderr=refused.stderr,
        payload_status=None,
        payload_body=None,
        archive_before=[],
        archive_after_negatives=[],
        archive_after=[],
        negatives={},
        exported=None,
        tagged=None,
        tag="",
        confirm_status=None,
        confirmed={},
        replay_status=None,
        replayed={},
        consumed_status=None,
        consumed_review={},
        ui_index=(None, b""),
        app_js=(None, b""),
    )


def _refused_restart_session(runtime: Path, refused, archive_root: Path):
    """Record a refused or unreachable restart without inventing a result."""

    return SimpleNamespace(
        runtime=runtime,
        readiness="" if refused is None else refused.readiness,
        startup_refusal=refused,
        stdout=b"" if refused is None else refused.stdout,
        stderr=b"" if refused is None else refused.stderr,
        payload_status=None,
        payload_body=None,
        old_review=(None, {}),
        old_confirm=(None, {}),
        archive_between=_archive_inventory(archive_root),
        archive_digests_between=_archive_digests(archive_root),
        replayed=None,
        tagged=None,
        tag="",
        confirm=(None, {}),
        archive_after=_archive_inventory(archive_root),
        archive_digests_after=_archive_digests(archive_root),
    )


def _enabled_session(
    installation,
    source,
    base: Path,
    *,
    config_file: Path,
    secret_file: Path,
    archive_root: Path,
    runtime_name: str,
) -> SimpleNamespace:
    runtime = base / runtime_name
    runtime.mkdir()
    arguments = [
        "--source-repository", str(source.path),
        "--required-source-head", source.head,
        "--run-parent", str(runtime / "runs"),
        "--contract-documents-directory", str(runtime / "contracts"),
        "--executable", "cursor-agent",
        "--attestation-class", "wrapper-chain",
        "--ui-port", "0", "--g2-port", "0", "--no-browser",
        "--historical-pairing-config", str(config_file),
        "--historical-pairing-secret-file", str(secret_file),
    ]
    negatives = {}
    try:
        launcher = InstalledLauncher(
            installation.scripts, arguments, cwd=runtime
        ).__enter__()
    except InstalledStartupRefused as refused:
        # A refused enabled startup is an acceptance observation, so it is
        # recorded here and asserted by the startup test rather than aborting
        # the whole module during fixture setup.
        return _refused_enabled_session(runtime, refused)
    try:
        readiness = launcher.readiness_line
        payload_status, payload_body = launcher.json_call("GET", PAYLOADS_ROUTE)
        archive_before = _archive_inventory(archive_root)

        # --- negative installed controls, each on its own preparation ----
        controls = _negative_controls(
            launcher, installation, base, secret_file
        )
        negatives.update(controls)
        archive_after_negatives = _archive_inventory(archive_root)

        # --- the accepted path -------------------------------------------
        exported = _prepare_and_export(launcher, base, "", index=0)
        tagged = _installed_tag(
            installation, exported.message_file, secret_file
        )
        assert tagged.returncode == 0, tagged.stderr
        tag = tagged.stdout.decode("ascii").rstrip("\r\n")
        confirm_status, confirmed = launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{exported.preparation_id}/confirmation",
            body={
                "expected_authority_fingerprint": exported.authority_fingerprint
            },
            extra={
                CSRF_HEADER: exported.csrf,
                CONFIRMATION_HEADER: tag,
            },
        )
        replay_status, replayed = launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{exported.preparation_id}/confirmation",
            body={
                "expected_authority_fingerprint": exported.authority_fingerprint
            },
            extra={
                CSRF_HEADER: exported.csrf,
                CONFIRMATION_HEADER: tag,
            },
        )
        consumed_status, consumed_review = launcher.json_call(
            "GET",
            f"{PREPARATIONS_ROUTE}/{exported.preparation_id}"
            f"/{exported.authority_fingerprint}",
        )
        ui_index_status, _ui_body, ui_index = launcher.call("GET", "/")
        app_status, _app_body, app_js = launcher.call("GET", "/ui/assets/app.js")
    finally:
        launcher.close()

    archive_after = _archive_inventory(archive_root)
    return SimpleNamespace(
        runtime=runtime,
        readiness=readiness,
        startup_refusal=None,
        stdout=launcher.stdout_bytes,
        stderr=launcher.stderr_bytes,
        payload_status=payload_status,
        payload_body=payload_body,
        archive_before=archive_before,
        archive_after_negatives=archive_after_negatives,
        archive_after=archive_after,
        negatives=negatives,
        exported=exported,
        tagged=tagged,
        tag=tag,
        confirm_status=confirm_status,
        confirmed=confirmed,
        replay_status=replay_status,
        replayed=replayed,
        consumed_status=consumed_status,
        consumed_review=consumed_review,
        ui_index=(ui_index_status, ui_index),
        app_js=(app_status, app_js),
    )


def _negative_controls(launcher, installation, base: Path, secret_file: Path):
    """Five independent preparations, each refused through a real request."""

    controls = {}

    wrong = _prepare_and_export(launcher, base, ".wrongtag", index=1)
    controls["wrong_tag"] = SimpleNamespace(
        exported=wrong,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{wrong.preparation_id}/confirmation",
            body={"expected_authority_fingerprint": wrong.authority_fingerprint},
            extra={CSRF_HEADER: wrong.csrf, CONFIRMATION_HEADER: "0" * 64},
        ),
    )

    upper = _prepare_and_export(launcher, base, ".uppercase", index=2)
    upper_tag = _installed_tag(
        installation, upper.message_file, secret_file
    ).stdout.decode("ascii").rstrip("\r\n")
    controls["uppercase_tag"] = SimpleNamespace(
        exported=upper,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{upper.preparation_id}/confirmation",
            body={"expected_authority_fingerprint": upper.authority_fingerprint},
            extra={
                CSRF_HEADER: upper.csrf,
                CONFIRMATION_HEADER: upper_tag.upper(),
            },
        ),
    )

    authorization = _prepare_and_export(launcher, base, ".authheader", index=3)
    authorization_tag = _installed_tag(
        installation, authorization.message_file, secret_file
    ).stdout.decode("ascii").rstrip("\r\n")
    controls["authorization_channel"] = SimpleNamespace(
        exported=authorization,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{authorization.preparation_id}/confirmation",
            body={
                "expected_authority_fingerprint": (
                    authorization.authority_fingerprint
                )
            },
            extra={
                CSRF_HEADER: authorization.csrf,
                "Authorization": "Bearer " + authorization_tag,
            },
        ),
    )

    body_channel = _prepare_and_export(launcher, base, ".bodytag", index=4)
    body_tag = _installed_tag(
        installation, body_channel.message_file, secret_file
    ).stdout.decode("ascii").rstrip("\r\n")
    controls["json_channel"] = SimpleNamespace(
        exported=body_channel,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{body_channel.preparation_id}/confirmation",
            body={
                "expected_authority_fingerprint": (
                    body_channel.authority_fingerprint
                ),
                "presented_confirmation_tag": body_tag,
            },
            extra={CSRF_HEADER: body_channel.csrf},
        ),
    )

    stale = _prepare_and_export(launcher, base, ".stalefp", index=5)
    stale_tag = _installed_tag(
        installation, stale.message_file, secret_file
    ).stdout.decode("ascii").rstrip("\r\n")
    controls["stale_fingerprint"] = SimpleNamespace(
        exported=stale,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{stale.preparation_id}/confirmation",
            body={"expected_authority_fingerprint": "f" * 64},
            extra={CSRF_HEADER: stale.csrf, CONFIRMATION_HEADER: stale_tag},
        ),
    )
    return controls


def _restart_session(
    installation,
    source,
    base: Path,
    *,
    config_file: Path,
    secret_file: Path,
    archive_root: Path,
    first,
) -> SimpleNamespace:
    runtime = base / "rt2"
    runtime.mkdir()
    if first.exported is None:
        # The first session never confirmed anything, so there is no restart
        # semantics to observe and nothing is invented in its place.
        return _refused_restart_session(runtime, None, archive_root)
    arguments = [
        "--source-repository", str(source.path),
        "--required-source-head", source.head,
        "--run-parent", str(runtime / "runs"),
        "--contract-documents-directory", str(runtime / "contracts"),
        "--executable", "cursor-agent",
        "--attestation-class", "wrapper-chain",
        "--ui-port", "0", "--g2-port", "0", "--no-browser",
        "--historical-pairing-config", str(config_file),
        "--historical-pairing-secret-file", str(secret_file),
    ]
    try:
        launcher = InstalledLauncher(
            installation.scripts, arguments, cwd=runtime
        ).__enter__()
    except InstalledStartupRefused as refused:
        return _refused_restart_session(runtime, refused, archive_root)
    try:
        readiness = launcher.readiness_line
        payload_status, payload_body = launcher.json_call("GET", PAYLOADS_ROUTE)
        old_review = launcher.json_call(
            "GET",
            f"{PREPARATIONS_ROUTE}/{first.exported.preparation_id}"
            f"/{first.exported.authority_fingerprint}",
        )
        csrf = launcher.csrf()
        old_confirm = launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{first.exported.preparation_id}/confirmation",
            body={
                "expected_authority_fingerprint": (
                    first.exported.authority_fingerprint
                )
            },
            extra={CSRF_HEADER: csrf, CONFIRMATION_HEADER: first.tag},
        )
        archive_between = _archive_inventory(archive_root)
        archive_digests_between = _archive_digests(archive_root)

        replayed = _prepare_and_export(launcher, base, "", index=6)
        tagged = _installed_tag(
            installation, replayed.message_file, secret_file
        )
        tag = tagged.stdout.decode("ascii").rstrip("\r\n")
        confirm = launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{replayed.preparation_id}/confirmation",
            body={
                "expected_authority_fingerprint": replayed.authority_fingerprint
            },
            extra={CSRF_HEADER: replayed.csrf, CONFIRMATION_HEADER: tag},
        )
    finally:
        launcher.close()

    return SimpleNamespace(
        runtime=runtime,
        readiness=readiness,
        startup_refusal=None,
        stdout=launcher.stdout_bytes,
        stderr=launcher.stderr_bytes,
        payload_status=payload_status,
        payload_body=payload_body,
        old_review=old_review,
        old_confirm=old_confirm,
        archive_between=archive_between,
        archive_digests_between=archive_digests_between,
        replayed=replayed,
        tagged=tagged,
        tag=tag,
        confirm=confirm,
        archive_after=_archive_inventory(archive_root),
        archive_digests_after=_archive_digests(archive_root),
    )


def _archive_digests(archive_root: Path) -> dict:
    if not archive_root.exists():
        return {}
    return {
        path.relative_to(archive_root).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in archive_root.rglob("*")
        if path.is_file()
    }


# ---------------------------------------------------------------------------
# B. Faithful distribution and isolated installation.
# ---------------------------------------------------------------------------


def test_exported_production_files_are_byte_identical_to_committed_blobs(workflow):
    for relative, (committed, exported) in (
        workflow.installation.export_identity.items()
    ):
        assert committed == exported, relative
    assert set(workflow.installation.export_identity) == set(
        COMMITTED_PRODUCTION_PATHS
    )


def test_every_isolated_import_origin_lies_under_the_installation(workflow):
    probe = workflow.installation.origins_probe
    assert probe.returncode == 0, (
        "the import-origin probe did not run inside the isolated installation: "
        f"{probe.stderr[-300:]!r}"
    )
    installation_root = str(workflow.installation.venv).lower()
    repository_root = str(REPO_ROOT).lower()
    assert set(workflow.installation.import_origins) == set(
        ISOLATED_IMPORT_ORIGINS
    )
    for module, origin in workflow.installation.import_origins.items():
        assert origin, module
        lowered = origin.lower()
        assert lowered.startswith(installation_root), (module, origin)
        assert not lowered.startswith(repository_root), (module, origin)


def test_all_four_console_scripts_are_installed_and_executable(workflow):
    scripts = workflow.installation.scripts
    for name in INSTALLED_CONSOLE_SCRIPTS:
        candidates = [scripts / f"{name}.exe", scripts / name]
        assert any(item.exists() for item in candidates), name
    # Every installed script really runs from the isolated installation.
    assert _run([str(scripts / "agent-os"), "--version"]).returncode == 0
    assert _run([str(scripts / "admissible"), "--help"]).returncode == 0
    for name in (
        "admissible-historical-pairing-tag",
        "admissible-historical-pairing-v4-extract",
    ):
        completed = _run([str(scripts / name), "--help"])
        assert completed.returncode == 0, name


def test_console_script_targets_remain_exactly_the_committed_declarations():
    declared = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = declared.split("[project.scripts]", 1)[1].split("\n\n", 1)[0]
    entries = dict(
        (part.strip().strip('"') for part in line.split("=", 1))
        for line in block.strip().splitlines()
        if "=" in line
    )
    assert entries == INSTALLED_CONSOLE_SCRIPTS


# ---------------------------------------------------------------------------
# C and D. External source repository and real provider-free wrapper.
# ---------------------------------------------------------------------------


def test_external_source_repository_is_clean_remote_free_and_outside_the_repo(
    workflow,
):
    source = workflow.source
    assert source.status == ""
    assert source.remotes == ""
    assert len(source.head) == 40
    assert REPO_ROOT not in source.path.resolve().parents


def test_real_preflight_only_envelope_is_the_acquired_wrapper_family(workflow):
    envelope = json.loads(workflow.wrapper.path.read_bytes().decode("utf-8"))
    assert workflow.wrapper.returncode == 0
    assert envelope["status"] == "PREFLIGHT_READY"
    assert set(envelope) == {
        "status",
        "authorization_payload",
        "attestation",
        "where_diagnostic",
        "durability_capability",
    }
    # The envelope is the product's own serialization, not a harness shape: the
    # captured child stdout is exactly one printed ``json.dumps(sort_keys=True)``
    # document plus the platform line terminator ``print`` added.
    assert workflow.wrapper.stdout.rstrip(b"\r\n") == (
        json.dumps(envelope, sort_keys=True).encode("utf-8")
    )
    assert workflow.wrapper.stdout.endswith(os.linesep.encode("ascii"))
    assert (
        envelope["attestation"]["attestation_class"] == "LOCAL_WRAPPER_CHAIN"
    ), "wrapper-chain attestation never executes the launcher bundle"


def test_wrapper_acquisition_started_no_run_and_produced_no_result(workflow):
    # Preflight-only returns before any run root is created, so no run state,
    # result, evidence record, or acceptance claim can exist.
    assert not workflow.wrapper.run_root.exists()
    for name in ("evidence", "workspace", "native-sidecar"):
        assert not (workflow.wrapper.run_root / name).exists()
    runs = workflow.contract.runtime / "runs"
    if runs.exists():
        assert list(runs.iterdir()) == []


# ---------------------------------------------------------------------------
# E. Installed standalone-V4 extraction.
# ---------------------------------------------------------------------------


def test_installed_extractor_emits_exactly_the_accepted_success_line(workflow):
    assert workflow.extracted.returncode == 0
    assert workflow.extracted.stdout == SUCCESS_LINE
    assert workflow.extracted.stderr == b""


def test_standalone_output_is_exact_canonical_form_a_without_wrapper(workflow):
    raw = workflow.standalone_bytes
    assert raw
    assert not raw.endswith(b"\n") and not raw.endswith(b"\r")
    document = json.loads(raw.decode("utf-8"))
    assert "authorization_payload" not in document
    for sibling in (
        "status",
        "attestation",
        "where_diagnostic",
        "durability_capability",
        "classification",
        "local_capability_status",
    ):
        assert sibling not in document
    reloaded = load_historical_native_canary_authorization_payload_v4(document)
    assert raw == canonical_bytes(reloaded.to_dict())
    envelope = json.loads(workflow.wrapper.path.read_bytes().decode("utf-8"))
    assert (
        reloaded.payload_fingerprint
        == envelope["authorization_payload"]["payload_fingerprint"]
    )
    assert len(raw) < MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES


def test_installed_extractor_refuses_to_overwrite_an_existing_output(workflow):
    assert workflow.not_overwritten.returncode == 3
    assert workflow.not_overwritten.stdout == b""
    assert workflow.not_overwritten.stderr == (
        b"error=HISTORICAL_PAIRING_V4_OUTPUT_EXISTS"
        + os.linesep.encode("ascii")
    )
    assert workflow.standalone.read_bytes() == workflow.standalone_bytes


def test_failed_status_wrapper_still_extracts_the_same_payload(workflow):
    assert workflow.failed_extract.returncode == 0
    assert workflow.failed_extract.stdout == SUCCESS_LINE
    assert workflow.failed_output.read_bytes() == workflow.standalone_bytes


def test_malformed_wrapper_never_creates_the_configured_output(workflow):
    assert workflow.malformed_extract.returncode == 3
    assert workflow.malformed_extract.stdout == b""
    assert workflow.malformed_extract.stderr == (
        b"error=HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED"
        + os.linesep.encode("ascii")
    )
    assert not workflow.malformed_output.exists()


def test_audited_extraction_touches_only_the_two_configured_paths(workflow):
    audit = workflow.audit
    assert audit.completed.returncode == 0, audit.completed.stderr
    assert audit.completed.stdout == SUCCESS_LINE
    touched = {line.split("|", 1)[1].lower() for line in audit.events}
    # Positive control first: a blind audit that recorded nothing must never be
    # mistaken for proof that no sibling was read.
    assert str(audit.wrapper).lower() in touched
    assert any(line.startswith("open|") for line in audit.events)
    assert touched <= {str(audit.wrapper).lower()}
    assert not any(
        line.startswith(("os.listdir|", "os.scandir|")) for line in audit.events
    )
    for sibling in ("native-execution.json", "behavioral-evidence.json", "notes.txt"):
        assert str(audit.directory / sibling).lower() not in touched
    assert audit.output.read_bytes() == workflow.standalone_bytes


# ---------------------------------------------------------------------------
# F. Exact secret and enablement configuration.
# ---------------------------------------------------------------------------


def test_secret_fixture_carries_text_hostile_bytes_inside_accepted_bounds(
    workflow,
):
    raw = workflow.secret_file.read_bytes()
    assert raw == SECRET_BYTES
    assert MIN_CONFIRMATION_SECRET_BYTES <= len(raw) <= MAX_CONFIRMATION_SECRET_BYTES
    assert b"\x00" in raw
    assert any(byte > 0x7F for byte in raw)
    assert b"\r" in raw and b"\n" in raw
    assert b" " in raw
    # Only a non-secret digest is ever recorded, and never in configuration.
    digest = hashlib.sha256(raw).hexdigest()
    assert len(digest) == 64
    assert digest.encode("ascii") not in workflow.config_bytes


def test_enablement_document_is_strict_utf8_without_bom(workflow):
    raw = workflow.config_bytes
    assert raw == workflow.config_file.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    document = json.loads(raw.decode("utf-8"))
    assert document["schema_version"] == HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION
    assert Path(document["archive_root"]).is_absolute()
    assert document["payloads"] == [
        {"payload_id": PAYLOAD_ID, "document_path": str(workflow.standalone)}
    ]
    assert 1 <= document["preparation_ttl_seconds"] <= 86_400
    assert 1 <= document["max_preparations"] <= 4_096
    assert SECRET_BYTES not in raw


# ---------------------------------------------------------------------------
# G. Real installed ProductLauncher startup.
# ---------------------------------------------------------------------------


def test_enabled_startup_reaches_readiness_and_discovers_the_payload(workflow):
    session = workflow.session
    assert session.startup_refusal is None, (
        "the installed launcher refused the configured historical pairing "
        f"startup: {session.stderr[-200:]!r}"
    )
    assert READINESS_PATTERN.match(session.readiness)
    assert session.payload_status == 200
    records = session.payload_body["payloads"]
    assert len(records) == 1
    record = records[0]
    assert record["payload_id"] == PAYLOAD_ID
    assert record["document_byte_length"] == len(workflow.standalone_bytes)
    assert record["document_sha256"] == hashlib.sha256(
        workflow.standalone_bytes
    ).hexdigest()
    document = json.loads(workflow.standalone_bytes.decode("utf-8"))
    assert record["payload_fingerprint"] == document["payload_fingerprint"]


def test_launcher_process_streams_never_carry_the_secret_or_the_tag(workflow):
    for stream in (
        workflow.session.stdout,
        workflow.session.stderr,
        workflow.restart.stdout,
        workflow.restart.stderr,
    ):
        assert _free_of(stream, SECRET_BYTES)
        assert _free_of(stream, workflow.session.tag.encode("ascii"))
        assert _free_of(stream, base64.b64encode(SECRET_BYTES))
        assert _free_of(stream, SECRET_BYTES.hex().encode("ascii"))
        assert _free_of(stream, CONFIRMATION_HEADER.encode("ascii"))


def test_disabled_feature_routes_match_the_ordinary_unknown_route(workflow):
    observed = workflow.disabled.observed
    unknown_get = observed["unknown_get"]
    unknown_post = observed["unknown_post"]
    assert unknown_get == (404, {"error": "NOT_FOUND"})
    for name in ("payloads", "review"):
        assert observed[name] == unknown_get, name
    assert unknown_post[0] == 404
    for name in ("prepare", "confirm"):
        assert observed[name] == unknown_post, name


def test_partial_historical_configuration_refuses_before_any_side_effect(
    workflow,
):
    for label, observed in workflow.partial.results.items():
        assert observed.completed.returncode == 3, label
        assert observed.completed.stdout == b"", label
        assert observed.completed.stderr == (
            b"error=HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE"
            + os.linesep.encode("ascii")
        ), label
        assert not observed.runtime_created, label
    assert not workflow.partial.runtime.exists()


# ---------------------------------------------------------------------------
# H. Preparation through the real loopback API.
# ---------------------------------------------------------------------------


def test_preparation_answers_with_the_complete_public_identity(workflow):
    identity = workflow.session.exported.identity
    document = json.loads(workflow.standalone_bytes.decode("utf-8"))
    assert identity["preparation_state"] == "READY_FOR_CONFIRMATION"
    assert identity["asserted_actor_id"] == ACTOR_ID
    assert identity["evaluation_profile_schema_version"] == (
        MISSION_PROFILE_SCHEMA_VERSION_V5
    )
    assert identity["evaluation_profile_is_launchable"] is False
    assert identity["target_authorization_payload_fingerprint"] == (
        document["payload_fingerprint"]
    )
    for name in (
        "preparation_id",
        "pairing_authority_fingerprint",
        "evaluation_profile_fingerprint",
    ):
        assert identity[name]


def test_complete_review_carries_every_owner_authored_field_exactly(workflow):
    review = workflow.session.exported.review
    material = _owner_material("")
    claims = review["claim_authority"]["claims"]
    assert claims == material["result_claims"]
    assert review["claim_authority"]["authorship"] == "OWNER_AUTHORED"
    assert review["claim_authority"]["coverage_status"] == "NOT_ASSESSED"
    obligations = review["verification_plan_authority"]["verification_obligations"]
    assert [item["obligation_id"] for item in obligations] == [
        member["obligation_id"] for member in material["claim_verification_plan"]
    ]
    assert obligations[0]["negative_controls"] == (
        material["claim_verification_plan"][0]["negative_controls"]
    )
    assert obligations[0]["independence_requirements"] == (
        material["claim_verification_plan"][0]["independence_requirements"]
    )
    bindings = review["verification_evidence_binding_authority"]["bindings"]
    assert bindings == material["verification_evidence_bindings"]
    assert review["verification_plan_authority"]["coverage_status"] == "NOT_ASSESSED"
    assert (
        review["verification_evidence_binding_authority"]["coverage_status"]
        == "NOT_ASSESSED"
    )


def test_review_states_historical_facts_and_withholds_every_local_locator(
    workflow,
):
    review = workflow.session.exported.review
    context = review["historical_authority_context"]
    document = json.loads(workflow.standalone_bytes.decode("utf-8"))
    assert context["target_authorization_payload_fingerprint"] == (
        document["payload_fingerprint"]
    )
    assert context["source_head"] == workflow.source.head
    assert context["backend_attestation_class"] == "LOCAL_WRAPPER_CHAIN"
    serialized = json.dumps(review, sort_keys=True)
    for withheld in review["withheld_fields"]:
        assert isinstance(withheld, str) and withheld
    assert str(workflow.source.path) not in serialized
    assert str(workflow.archive_root) not in serialized
    assert str(workflow.standalone) not in serialized
    assert str(workflow.secret_file) not in serialized


def test_review_asserts_no_execution_result_or_authenticated_actor(workflow):
    review = workflow.session.exported.review
    notices = review["notices"]
    assert any("actor_id is an asserted identifier" in item for item in notices)
    assert any("authorizes no execution" in item for item in notices)
    assert any(
        "does not prove fresh secret possession" in item for item in notices
    )
    assert any("is not a digital signature" in item for item in notices)
    assert any(
        "never proves that a confirmation tag was presented" in item
        for item in notices
    )
    assert any(
        "vanish on launcher restart" in item for item in notices
    )
    # ``withheld_fields`` is the review's own published statement of what it
    # deliberately does not carry, so it names those members on purpose. The
    # forbidden scan runs over everything else.
    body = {key: value for key, value in review.items() if key != "withheld_fields"}
    serialized = json.dumps(body, sort_keys=True)
    for forbidden in (
        "ADMITTED_OBSERVED",
        "ADMITTED_VERIFIED",
        "product_verdict",
        "confirmation_tag",
        "expected_tag",
        "presented_tag",
    ):
        assert forbidden not in serialized, forbidden
    assert "historical_pairing_confirmation.expected_tag" in review["withheld_fields"]
    assert SECRET_BYTES not in json.dumps(review, sort_keys=True).encode("utf-8")
    assert workflow.session.tag not in json.dumps(review, sort_keys=True)


# ---------------------------------------------------------------------------
# I. Public confirmation-message export.
# ---------------------------------------------------------------------------


def test_exported_confirmation_message_matches_declared_integrity_metadata(
    workflow,
):
    identity = workflow.session.exported.review["pairing_identity"]
    message = workflow.session.exported.message
    assert base64.b64decode(
        identity["confirmation_message_base64"], validate=True
    ) == message
    assert identity["confirmation_message_byte_length"] == len(message)
    assert identity["confirmation_message_sha256"] == hashlib.sha256(
        message
    ).hexdigest()
    assert workflow.session.exported.message_file.read_bytes() == message


def test_exported_message_is_the_accepted_already_domain_separated_bytes(
    workflow,
):
    message = workflow.session.exported.message
    prefix = (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
        + HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR
    )
    assert message.startswith(prefix)
    authority_bytes = message[len(prefix):]
    authority = json.loads(authority_bytes.decode("utf-8"))
    assert authority["authority_fingerprint"] == (
        workflow.session.exported.authority_fingerprint
    )
    # The independent oracle rebuilds the same bytes from the archived
    # authority, so the harness never adds a domain or separator of its own.
    bundle = load_historical_evaluation_pairing(
        archive_root=workflow.archive_root,
        authority_fingerprint=workflow.session.exported.authority_fingerprint,
    )
    assert message == build_historical_pairing_confirmation_message(
        pairing_authority=bundle.pairing_authority
    )
    assert workflow.session.exported.identity["confirmation_message_recipe"]


def test_visible_download_action_exposes_the_same_launcher_supplied_bytes(
    workflow,
):
    """A bounded installed-process smoke over the served UI, not a browser run.

    The served page and script are read from the running installed launcher.
    They are checked for exactly the wiring that turns the launcher-supplied
    Base64 into the downloaded bytes; no browser is driven here, so this is not
    presented as an end-to-end browser proof.
    """

    index_status, index_html = workflow.session.ui_index
    app_status, app_js = workflow.session.app_js
    assert index_status == 200 and app_status == 200
    assert b'id="historical-download-message"' in index_html
    assert b"historicalDownloadMessage" in app_js
    assert b'hpOn("historical-download-message","click",historicalDownloadMessage)' in app_js
    assert b'hpIdentityValue("confirmation_message_base64")' in app_js
    assert b"atob(base64)" in app_js
    assert b"bytes.length!==declared" in app_js
    assert _free_of(app_js, SECRET_BYTES)
    assert _free_of(app_js, workflow.session.tag.encode("ascii"))


# ---------------------------------------------------------------------------
# J. Independent installed tag computation.
# ---------------------------------------------------------------------------


def test_installed_tag_helper_prints_exactly_one_lowercase_hex_tag(workflow):
    tagged = workflow.session.tagged
    # The tag under test must have come from the installed console script in the
    # isolated installation, never from an in-harness computation.
    executable = Path(tagged.args[0])
    assert executable.parent == workflow.installation.scripts, tagged.args[0]
    assert executable.stem == "admissible-historical-pairing-tag", tagged.args[0]
    assert list(tagged.args[1:]) == [
        "--message-file",
        str(workflow.session.exported.message_file),
        "--secret-file",
        str(workflow.secret_file),
    ]
    assert tagged.returncode == 0
    assert tagged.stderr == b""
    assert tagged.stdout == workflow.session.tag.encode("ascii") + os.linesep.encode(
        "ascii"
    )
    assert len(workflow.session.tag) == 64
    assert all(character in "0123456789abcdef" for character in workflow.session.tag)


def test_installed_tag_matches_the_accepted_confirmation_primitive(workflow):
    bundle = load_historical_evaluation_pairing(
        archive_root=workflow.archive_root,
        authority_fingerprint=workflow.session.exported.authority_fingerprint,
    )
    expected = compute_historical_pairing_confirmation_tag(
        secret=SECRET_BYTES, pairing_authority=bundle.pairing_authority
    )
    assert hmac.compare_digest(expected, workflow.session.tag)
    assert workflow.session.tag == hmac.new(
        key=SECRET_BYTES,
        msg=workflow.session.exported.message,
        digestmod=hashlib.sha256,
    ).hexdigest()


def test_tag_helper_reaches_no_socket_and_no_product_module(workflow):
    module = (
        workflow.installation.venv
        / "Lib"
        / "site-packages"
        / "admissible"
        / "operator_tools"
        / "historical_pairing_tag.py"
    )
    if not module.exists():  # pragma: no cover - non-Windows layout
        matches = list(
            workflow.installation.venv.rglob(
                "admissible/operator_tools/historical_pairing_tag.py"
            )
        )
        assert matches
        module = matches[0]
    source = module.read_text(encoding="utf-8")
    for forbidden in (
        "socket",
        "http",
        "urllib",
        "requests",
        "product_launcher",
        "delegated_gate",
        "archive",
    ):
        assert f"import {forbidden}" not in source, forbidden
    guard = workflow.base / "socketguard"
    guard.mkdir(exist_ok=True)
    (guard / "sitecustomize.py").write_text(
        "import socket\n"
        "class _Refused(RuntimeError):\n"
        "    pass\n"
        "def _refuse(*_args, **_kwargs):\n"
        "    raise _Refused('the tag helper must not open a socket')\n"
        "socket.socket = _refuse\n"
        "socket.create_connection = _refuse\n",
        encoding="utf-8",
    )
    completed = _run(
        [
            str(workflow.installation.python),
            "-m",
            "admissible.operator_tools.historical_pairing_tag",
            "--message-file", str(workflow.session.exported.message_file),
            "--secret-file", str(workflow.secret_file),
        ],
        cwd=workflow.base,
        env={"PYTHONPATH": str(guard)},
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == b""
    assert completed.stdout == (
        workflow.session.tag.encode("ascii") + os.linesep.encode("ascii")
    )


def test_no_tag_is_persisted_anywhere_by_the_workflow(workflow):
    tag = workflow.session.tag.encode("ascii")
    restart_tag = workflow.restart.tag.encode("ascii")
    for path in sorted(workflow.base.rglob("*")):
        if not path.is_file():
            continue
        if path == workflow.installation.wheel:
            continue
        raw = path.read_bytes()
        assert _free_of(raw, tag), path
        assert _free_of(raw, restart_tag), path


# ---------------------------------------------------------------------------
# K. Real confirmation submission and installed negative controls.
# ---------------------------------------------------------------------------


def test_dedicated_header_confirmation_reaches_the_archive_available_state(
    workflow,
):
    session = workflow.session
    assert session.confirm_status == 200, session.confirmed
    assert session.confirmed["outcome"] == "CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE"
    assert session.confirmed["preparation_id"] == session.exported.preparation_id
    assert session.confirmed["asserted_actor_id"] == ACTOR_ID
    assert session.confirmed["archived_pairing_document_count"] == 3
    assert session.confirmed["pairing_authority_fingerprint"] == (
        session.exported.authority_fingerprint
    )
    body = json.dumps(session.confirmed, sort_keys=True)
    assert session.tag not in body
    assert "tag" not in {key.lower() for key in session.confirmed}


def test_consumed_preparation_refuses_a_second_confirmation(workflow):
    assert workflow.session.replay_status == 409
    assert workflow.session.replayed == {"error": "PREPARATION_CONSUMED"}
    assert workflow.session.consumed_status == 200
    assert (
        workflow.session.consumed_review["pairing_identity"]["preparation_state"]
        == "CONSUMED"
    )


@pytest.mark.parametrize(
    "control,expected",
    [
        ("wrong_tag", (403, {"error": "CONFIRMATION_REJECTED"})),
        ("uppercase_tag", (400, {"error": "CONFIRMATION_TAG_MALFORMED"})),
        ("authorization_channel", (400, {"error": "CONFIRMATION_TAG_REQUIRED"})),
        ("json_channel", (400, {"error": "INVALID_FIELDS"})),
        ("stale_fingerprint", (409, {"error": "STALE_AUTHORITY_FINGERPRINT"})),
    ],
)
def test_installed_negative_controls_are_refused_exactly(
    workflow, control, expected
):
    assert workflow.session.negatives[control].response == expected


def test_every_negative_control_left_the_archive_unpublished(workflow):
    assert workflow.session.archive_before == []
    assert workflow.session.archive_after_negatives == []
    published = set(workflow.session.archive_after)
    for name, control in workflow.session.negatives.items():
        fingerprint = control.exported.authority_fingerprint
        profile = control.exported.identity["evaluation_profile_fingerprint"]
        assert not any(fingerprint in item for item in published), name
        assert not any(profile in item for item in published), name


# ---------------------------------------------------------------------------
# L. Exact archive verification.
# ---------------------------------------------------------------------------


def test_archive_holds_exactly_the_three_canonical_documents(workflow):
    exported = workflow.session.exported
    profile_fingerprint = exported.identity["evaluation_profile_fingerprint"]
    payload_fingerprint = exported.identity[
        "target_authorization_payload_fingerprint"
    ]
    expected = sorted(
        [
            f"{PROFILE_DIRECTORY_NAME}/{profile_fingerprint}{PROFILE_FILE_SUFFIX}",
            f"{PAYLOAD_DIRECTORY_NAME}/{payload_fingerprint}{PAYLOAD_FILE_SUFFIX}",
            f"{AUTHORITY_DIRECTORY_NAME}/{exported.authority_fingerprint}"
            f"{AUTHORITY_FILE_SUFFIX}",
        ]
    )
    assert workflow.session.archive_after == expected
    assert len(list(workflow.archive_root.rglob("*.json"))) == 3


def test_archived_documents_are_exact_canonical_bytes_matching_fingerprints(
    workflow,
):
    exported = workflow.session.exported
    payload_fingerprint = exported.identity[
        "target_authorization_payload_fingerprint"
    ]
    payload_path = (
        workflow.archive_root
        / PAYLOAD_DIRECTORY_NAME
        / f"{payload_fingerprint}{PAYLOAD_FILE_SUFFIX}"
    )
    assert payload_path.read_bytes() == workflow.standalone_bytes
    bundle = load_historical_evaluation_pairing(
        archive_root=workflow.archive_root,
        authority_fingerprint=exported.authority_fingerprint,
    )
    profile = bundle.evaluation_profile
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5
    assert profile.is_launchable_runtime_profile is False
    assert profile.profile_fingerprint == (
        exported.identity["evaluation_profile_fingerprint"]
    )
    authority = bundle.pairing_authority
    assert authority.evaluation_profile_fingerprint == profile.profile_fingerprint
    assert authority.target_authorization_payload_fingerprint == payload_fingerprint
    assert authority.actor_id == ACTOR_ID
    projected = project_v5_runtime_authority_to_v2(profile)
    embedded = bundle.target_authorization_payload.mission_profile
    assert canonical_bytes(projected.to_dict()) == canonical_bytes(
        embedded.to_dict()
    )
    assert projected.profile_fingerprint == embedded.profile_fingerprint
    profile_path = (
        workflow.archive_root
        / PROFILE_DIRECTORY_NAME
        / f"{profile.profile_fingerprint}{PROFILE_FILE_SUFFIX}"
    )
    authority_path = (
        workflow.archive_root
        / AUTHORITY_DIRECTORY_NAME
        / f"{authority.authority_fingerprint}{AUTHORITY_FILE_SUFFIX}"
    )
    assert profile_path.read_bytes() == canonical_bytes(profile.to_dict())
    assert authority_path.read_bytes() == canonical_bytes(authority.to_dict())


def test_archive_holds_no_receipt_manifest_or_secret_derived_material(workflow):
    names = set(workflow.session.archive_after)
    for forbidden in (
        "receipt",
        "manifest",
        "status",
        "confirmation",
        "tag",
        "secret",
        "actor",
        "result",
        "verdict",
    ):
        assert not any(forbidden in name.lower() for name in names), forbidden
    tag = workflow.session.tag
    for path in workflow.archive_root.rglob("*"):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        assert _free_of(raw, SECRET_BYTES), path
        assert _free_of(raw, tag.encode("ascii")), path
        assert _free_of(raw, bytes.fromhex(tag)), path
        assert _free_of(raw, base64.b64encode(SECRET_BYTES)), path
        assert _free_of(raw, SECRET_BYTES.hex().encode("ascii")), path
        assert _free_of(raw, CONFIRMATION_HEADER.encode("ascii")), path


def test_no_product_created_file_anywhere_carries_the_secret(workflow):
    """Scan every product-created file, excluding operator-selected sources."""

    operator_selected = {
        workflow.secret_file.resolve(),
        workflow.config_file.resolve(),
        workflow.standalone.resolve(),
        workflow.wrapper.path.resolve(),
        workflow.session.exported.message_file.resolve(),
        workflow.restart.replayed.message_file.resolve(),
    }
    for control in workflow.session.negatives.values():
        operator_selected.add(control.exported.message_file.resolve())
    scanned = 0
    for path in sorted(workflow.base.rglob("*")):
        if not path.is_file() or path.resolve() in operator_selected:
            continue
        if path == workflow.installation.wheel:
            continue
        raw = path.read_bytes()
        assert _free_of(raw, SECRET_BYTES), path
        assert _free_of(raw, base64.b64encode(SECRET_BYTES)), path
        assert _free_of(raw, SECRET_BYTES.hex().encode("ascii")), path
        scanned += 1
    assert scanned > 0


# ---------------------------------------------------------------------------
# M. Restart semantics and deterministic replay.
# ---------------------------------------------------------------------------


def test_restart_reaches_readiness_and_still_discovers_the_payload(workflow):
    assert READINESS_PATTERN.match(workflow.restart.readiness)
    assert workflow.restart.payload_status == 200
    assert workflow.restart.payload_body == workflow.session.payload_body


def test_restart_never_reconstructs_the_old_preparation_from_the_archive(
    workflow,
):
    assert workflow.restart.old_review == (404, {"error": "PREPARATION_NOT_FOUND"})
    assert workflow.restart.old_confirm == (
        404,
        {"error": "PREPARATION_NOT_FOUND"},
    )
    assert workflow.restart.archive_between == workflow.session.archive_after


def test_identical_owner_inputs_replay_the_exact_same_authority_and_tag(
    workflow,
):
    first = workflow.session.exported
    again = workflow.restart.replayed
    assert again.preparation_id != first.preparation_id
    assert again.authority_fingerprint == first.authority_fingerprint
    assert (
        again.identity["evaluation_profile_fingerprint"]
        == first.identity["evaluation_profile_fingerprint"]
    )
    assert (
        again.identity["target_authorization_payload_fingerprint"]
        == first.identity["target_authorization_payload_fingerprint"]
    )
    assert again.message == first.message
    assert workflow.restart.tag == workflow.session.tag


def test_replayed_confirmation_is_idempotent_over_the_exact_archive(workflow):
    status, body = workflow.restart.confirm
    assert status == 200, body
    assert body["outcome"] == "CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE"
    assert body["archived_pairing_document_count"] == 3
    assert workflow.restart.archive_after == workflow.session.archive_after
    assert workflow.restart.archive_digests_after == (
        workflow.restart.archive_digests_between
    )
    assert len(workflow.restart.archive_after) == 3


def test_deterministic_replay_states_exactly_what_it_does_not_prove(workflow):
    limitations = workflow.restart.confirm[1]["limitations"]
    assert any(
        "does not prove fresh secret possession" in item for item in limitations
    )
    assert any(
        "actor_id is an asserted identifier" in item for item in limitations
    )
    assert any("is not a digital signature" in item for item in limitations)
    assert any(
        "never proves that a tag was presented" in item for item in limitations
    )
    assert any(
        "says nothing about execution" in item for item in limitations
    )
    assert any(
        "does not state whether the archive was published now" in item
        for item in limitations
    )


# ---------------------------------------------------------------------------
# N. Filesystem confidentiality and non-persistence.
# ---------------------------------------------------------------------------


def test_only_the_expected_operator_and_product_material_exists(workflow):
    archive_files = _archive_inventory(workflow.archive_root)
    assert len(archive_files) == 3
    suspicious = []
    for path in workflow.base.rglob("*"):
        if not path.is_file():
            continue
        lowered = path.name.lower()
        if any(
            marker in lowered
            for marker in ("receipt", "confirmation-receipt", "tagfile", "debug-dump")
        ):
            suspicious.append(path)
    assert suspicious == []
    assert not (workflow.session.runtime / "historical").exists()
    assert not (workflow.restart.runtime / "historical").exists()


def test_no_child_process_argv_or_environment_carried_the_secret(workflow):
    """Scan the exact argv and environment overlays this workflow handed out."""

    assert SPAWNED_ARGV, "no child process was recorded"
    encodings = (
        SECRET_BYTES,
        base64.b64encode(SECRET_BYTES),
        SECRET_BYTES.hex().encode("ascii"),
        workflow.session.tag.encode("ascii"),
        workflow.restart.tag.encode("ascii"),
    )
    for argv in SPAWNED_ARGV:
        joined = " ".join(argv).encode("utf-8", "surrogateescape")
        for material in encodings:
            assert _free_of(joined, material), argv[:2]
    for overlay in SPAWNED_ENVIRONMENT_OVERLAYS:
        for name, value in overlay.items():
            encoded = str(value).encode("utf-8", "surrogateescape")
            for material in encodings:
                assert _free_of(encoded, material), name
    for name, value in os.environ.items():
        assert SECRET_BYTES not in value.encode("utf-8", "ignore"), name
        assert workflow.session.tag not in value, name


# ---------------------------------------------------------------------------
# O and P. Operator runbook and its command verification.
# ---------------------------------------------------------------------------


def _runbook_text() -> str:
    assert RUNBOOK_PATH.is_file(), RUNBOOK_PATH
    return RUNBOOK_PATH.read_text(encoding="utf-8")


def _fenced_blocks(text: str, language: str) -> list[str]:
    return re.findall(
        r"^```" + language + r"\s*\n(.*?)^```\s*$", text, re.M | re.S
    )


def _installed_flags(installation, script: str) -> set[str]:
    completed = _run([str(installation.scripts / script), "--help"])
    assert completed.returncode == 0, script
    return set(
        re.findall(r"--[a-z0-9][a-z0-9-]*", completed.stdout.decode("utf-8"))
    )


def test_runbook_exists_and_covers_every_required_operator_stage():
    text = _runbook_text()
    for heading in (
        "Prerequisites and trust model",
        "Locate one real wrapper",
        "Extract the standalone V4 document",
        "Create the exact-byte secret file",
        "Create the enablement document",
        "Launch Admissible",
        "Review the configured payload",
        "Author claims, plans and bindings",
        "Prepare and review the pairing authority",
        "Export the public confirmation message",
        "Verify the message length and SHA-256",
        "Compute the tag",
        "Paste the tag",
        "Confirm",
        "Verify the three archive documents",
        "Restart",
        "Safe retry and cleanup",
        "Known limitations and non-claims",
    ):
        assert heading in text, heading


def test_runbook_states_every_required_warning():
    text = _runbook_text().lower()
    for warning in (
        "absolute",
        "no parent directory is created",
        "create-only",
        "partial output",
        "newline and nul",
        "byte order mark",
        "never place the secret in a command line argument",
        "do not redirect the tag",
        "already includes the domain",
        "do not prepend",
        "deterministic and replayable",
        "not a signature",
        "asserted",
        "not an execution",
        "restart loses",
        "not a confirmation receipt",
    ):
        assert warning in text, warning


def test_runbook_never_contains_a_real_secret_tag_or_acceptance_path():
    text = _runbook_text()
    assert SECRET_BYTES.hex() not in text
    assert base64.b64encode(SECRET_BYTES).decode("ascii") not in text
    assert not re.search(r"\b[0-9a-f]{64}\b", text), (
        "the runbook must never contain a literal 64-hex tag or fingerprint"
    )
    for machine_specific in ("AppData\\Local\\Temp", "s5c2e3", str(REPO_ROOT)):
        assert machine_specific not in text, machine_specific
    assert "<" in text and ">" in text, "placeholders must be clearly marked"


def test_runbook_never_claims_authentication_possession_or_execution():
    """The runbook must not assert anything the mechanism cannot establish."""

    lowered = _runbook_text().lower()
    for forbidden in (
        "authenticates the actor",
        "the actor is authenticated",
        "verified identity",
        "proof of identity",
        "proves the execution",
        "proves that the run",
        "is a digital signature",
        "confirmation receipt for",
    ):
        assert forbidden not in lowered, forbidden
    # A possession claim is refused unless it is explicitly negated.
    possession = re.search(
        r"(?<!not )(?<!never )(?<!cannot )prove[sd]? fresh secret possession",
        lowered,
    )
    assert possession is None, lowered[
        max(0, possession.start() - 60) : possession.end()
    ] if possession else ""
    assert "does not prove fresh secret possession" in lowered


def test_runbook_commands_match_the_installed_command_line_surface(workflow):
    text = _runbook_text()
    blocks = _fenced_blocks(text, "powershell")
    assert blocks, "the runbook must carry executable PowerShell blocks"
    joined = "\n".join(blocks)
    launcher_flags = _installed_flags(workflow.installation, "admissible")
    tag_flags = _installed_flags(
        workflow.installation, "admissible-historical-pairing-tag"
    )
    extract_flags = _installed_flags(
        workflow.installation, "admissible-historical-pairing-v4-extract"
    )
    documented = {
        "admissible": set(),
        "admissible-historical-pairing-tag": set(),
        "admissible-historical-pairing-v4-extract": set(),
    }
    current: str | None = None
    for line in joined.splitlines():
        stripped = line.strip()
        for name in documented:
            if stripped.startswith(name + " ") or stripped == name:
                current = name
                break
        else:
            if stripped and not stripped.startswith(("--", "`", "#")):
                current = None
        if current is not None:
            documented[current].update(
                re.findall(r"--[a-z0-9][a-z0-9-]*", stripped)
            )
    assert documented["admissible"] <= launcher_flags, (
        documented["admissible"] - launcher_flags
    )
    assert documented["admissible-historical-pairing-tag"] == {
        "--message-file",
        "--secret-file",
    }
    assert documented["admissible-historical-pairing-v4-extract"] == {
        "--wrapper-file",
        "--output-file",
    }
    for required in (
        "--source-repository",
        "--required-source-head",
        "--run-parent",
        "--contract-documents-directory",
        "--executable",
        "--no-browser",
        "--historical-pairing-config",
        "--historical-pairing-secret-file",
    ):
        assert required in documented["admissible"], required
    assert tag_flags >= {"--message-file", "--secret-file"}
    assert extract_flags >= {"--wrapper-file", "--output-file"}


def test_runbook_names_the_exact_routes_and_confirmation_header():
    text = _runbook_text()
    for token in (
        PAYLOADS_ROUTE,
        PREPARATIONS_ROUTE,
        CONFIRMATION_HEADER,
        PROFILE_FILE_SUFFIX,
        PAYLOAD_FILE_SUFFIX,
        AUTHORITY_FILE_SUFFIX,
        HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
        "status=STANDALONE_V4_WRITTEN",
    ):
        assert token in text, token


def test_runbook_powershell_snippets_execute_with_the_documented_semantics(
    workflow, tmp_path
):
    if shutil.which("powershell") is None:  # pragma: no cover - honest skip
        pytest.skip("PowerShell is required to verify the documented snippets")
    text = _runbook_text()
    blocks = _fenced_blocks(text, "powershell")
    joined = "\n".join(blocks)

    secret_snippet = _extract_snippet(joined, "WriteAllBytes", "secret")
    assert "New-Object byte[]" in secret_snippet or "byte[]" in secret_snippet
    secret_path = tmp_path / "secret.bin"
    executed = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            secret_snippet.replace("<SECRET-FILE>", str(secret_path)),
        ],
        timeout=180,
    )
    assert executed.returncode == 0, executed.stderr[-400:]
    assert secret_path.exists()
    assert MIN_CONFIRMATION_SECRET_BYTES <= secret_path.stat().st_size <= (
        MAX_CONFIRMATION_SECRET_BYTES
    )

    enablement_snippet = _extract_snippet(joined, "UTF8Encoding", "enablement")
    config_path = tmp_path / "historical-pairing.json"
    executed = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            enablement_snippet
            .replace("<ENABLEMENT-FILE>", str(config_path))
            .replace("<ARCHIVE-ROOT>", str(tmp_path / "archive"))
            .replace("<STANDALONE-V4-FILE>", str(tmp_path / "standalone-v4.json")),
        ],
        timeout=180,
    )
    assert executed.returncode == 0, executed.stderr[-400:]
    raw = config_path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    document = json.loads(raw.decode("utf-8"))
    assert document["schema_version"] == HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION

    message_snippet = _extract_snippet(joined, "FromBase64String", "message")
    message_path = tmp_path / "confirmation-message.bin"
    executed = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            message_snippet
            .replace(
                "<CONFIRMATION-MESSAGE-BASE64>",
                base64.b64encode(workflow.session.exported.message).decode("ascii"),
            )
            .replace("<CONFIRMATION-MESSAGE-FILE>", str(message_path)),
        ],
        timeout=180,
    )
    assert executed.returncode == 0, executed.stderr[-400:]
    assert message_path.read_bytes() == workflow.session.exported.message

    tagged = _run(
        [
            str(workflow.installation.scripts / "admissible-historical-pairing-tag"),
            "--message-file", str(message_path),
            "--secret-file", str(workflow.secret_file),
        ]
    )
    assert tagged.returncode == 0
    assert tagged.stdout.decode("ascii").rstrip("\r\n") == workflow.session.tag


def _extract_snippet(joined: str, marker: str, label: str) -> str:
    """Return the one documented PowerShell statement group carrying *marker*."""

    candidates = [
        block.strip()
        for block in joined.split("\n\n")
        if marker in block
    ]
    assert candidates, f"the runbook must document a {label} snippet using {marker}"
    return candidates[0]


def test_runbook_archive_verification_command_is_real(workflow):
    text = _runbook_text()
    assert "Get-ChildItem" in text
    completed = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Get-ChildItem -Recurse -File '{workflow.archive_root}' | "
            "Measure-Object | Select-Object -ExpandProperty Count",
        ],
        timeout=180,
    ) if shutil.which("powershell") else None
    if completed is not None:
        assert completed.returncode == 0, completed.stderr[-400:]
        assert completed.stdout.decode("utf-8").strip() == "3"


# ---------------------------------------------------------------------------
# Q. Real-process and port hygiene.
# ---------------------------------------------------------------------------


def test_every_launcher_process_terminated_and_released_its_ports(workflow):
    for runtime in (workflow.session.runtime, workflow.restart.runtime):
        assert runtime.exists()
    # A closed launcher must leave its loopback ports free again.
    for port_holder in (workflow.session, workflow.restart):
        match = READINESS_PATTERN.match(port_holder.readiness)
        assert match
        for candidate in (int(match.group(1)), int(match.group(2))):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.settimeout(2.0)
                assert probe.connect_ex(("127.0.0.1", candidate)) != 0, candidate
            finally:
                probe.close()
