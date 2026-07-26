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

Environment support versus product refusal
------------------------------------------

Whether this host can run the workflow at all is decided *before* any product
process is started, from explicit independently observed prerequisites only.
Once that predicate has passed, every product outcome is an acceptance
observation: a nonzero preflight or wrapper return code, malformed wrapper
stdout, an unexpected exception, or a created run root is a **test failure**,
never a skip.  Wrapper-result validation is a separate function that contains no
``pytest.skip``, ``pytest.xfail`` or ``pytest.importorskip``, and the whole
post-support region runs inside a guard that turns any skip attempt into a
failure.  A supported-host product regression can therefore never present itself
as a green selection with the load-bearing tests skipped.

Browser evidence: what is and is not proven
-------------------------------------------

The committed browser evidence is a **served-asset smoke**: the launcher really
serves the page and the script, the download button wiring really exists, and
the script really decodes the launcher-supplied Base64 and compares the decoded
length against the declared length.  No browser is driven here, so this is
**not a real-browser end-to-end proof** that a download completed.  The operator
performs the browser download interactively.  A wording guard refuses any
runbook or docstring sentence that would upgrade this served-asset smoke into a
claim that some automated client completed the download.
"""

from __future__ import annotations

import ast
import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import ntpath
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
    HistoricalEvaluationPairingAuthority,
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
from admissible.delegated_gate.native_executor import (
    ATTESTATION_CLASS_WRAPPER_CHAIN,
    CURSOR_DISCOVERY_COMMAND,
)
from admissible.product_launcher.historical_pairing_enablement import (
    HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
)
from admissible.product_launcher.historical_pairing_registry import (
    MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES,
)
from admissible.product_launcher.preflight_runner import (
    WRAPPER_ARGUMENT_ERROR,
    WRAPPER_INTERNAL_ERROR,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_PATH = REPO_ROOT / "docs" / "runbooks" / "historical_pairing_operator.md"
MODULE_PATH = Path(__file__).resolve()

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

# The exact argparse failure code the installed preflight CLI returns for a
# contract violation, and the exact code its bare ``except Exception`` returns
# for an internal fault.  Both are product outcomes, never host conditions.
PREFLIGHT_CLI_CONTRACT_EXIT = WRAPPER_ARGUMENT_ERROR
PREFLIGHT_INTERNAL_EXIT = WRAPPER_INTERNAL_ERROR
PREFLIGHT_ARGPARSE_EXIT = 2

# Exactly the ordered boundary a public confirmation-message export must clear
# before the installed tag helper is allowed to start.
PUBLIC_MESSAGE_VERIFICATION_ORDER = (
    "PUBLIC_EXPORT_READ",
    "STRICT_BASE64_DECODE",
    "LENGTH_VERIFIED",
    "SHA256_VERIFIED",
    "DOMAIN_VERIFIED",
    "NUL_BOUNDARY_VERIFIED",
    "ORACLE_EQUALITY_VERIFIED",
    "MESSAGE_FILE_WRITTEN",
    "INSTALLED_TAG_HELPER_STARTED",
    "CONFIRMATION_SUBMITTED",
)

# The one accepted skip reason for a missing PowerShell interpreter.  It is
# scoped to the runbook-command execution tests and to nothing else.
POWERSHELL_SKIP_REASON = (
    "PowerShell is unavailable, so the documented PowerShell runbook commands "
    "cannot be executed on this host"
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


def _bounded_diagnostic(blob: bytes, *, limit: int = 400) -> str:
    """Render a short, non-secret tail of a captured stream for a failure."""

    text = blob[-limit:].decode("utf-8", "replace")
    for material in (
        SECRET_BYTES.decode("latin-1"),
        base64.b64encode(SECRET_BYTES).decode("ascii"),
        SECRET_BYTES.hex(),
    ):
        text = text.replace(material, "<redacted>")
    return text


# ---------------------------------------------------------------------------
# 1. Environment-support classification -- decided before any product process.
# ---------------------------------------------------------------------------


def _deterministically_resolvable_backend() -> str | None:
    """Locate the accepted local backend exactly where the contract requires it.

    The wrapper-chain attestation resolves ``cursor-agent`` from the process
    ``PATH``/``PATHEXT`` and cross-checks that winner against ``shutil.which``.
    This predicate observes exactly that discovery surface and nothing else, so
    "no accepted backend on this host" can never be confused with "the product
    refused".
    """

    return shutil.which(CURSOR_DISCOVERY_COMMAND, path=os.environ.get("PATH", ""))


def classify_operator_host_support() -> tuple[str, ...]:
    """Return the ordered explicit reasons this host cannot run the workflow.

    Every reason is an independently observed prerequisite.  No reason is ever
    inferred from a product process return code, a product refusal, a product
    exception, or any captured product output.
    """

    reasons: list[str] = []
    if os.name != "nt":
        reasons.append(
            "os.name is not 'nt'; the installed operator runbook targets a "
            "Windows operator"
        )
    for tool in ("git", "tar"):
        if shutil.which(tool) is None:
            reasons.append(
                f"the {tool} executable is absent, so the faithful export "
                "cannot be built"
            )
    if _deterministically_resolvable_backend() is None:
        reasons.append(
            f"the accepted local backend command {CURSOR_DISCOVERY_COMMAND!r} "
            "is not discoverable on PATH/PATHEXT, where the provider-free "
            "wrapper contract requires it"
        )
    return tuple(reasons)


def _require_supported_operator_host() -> None:
    """The one pre-invocation environment gate for the installed workflow."""

    reasons = classify_operator_host_support()
    if reasons:  # pragma: no cover - environment honest, pre-invocation only
        pytest.skip("unsupported operator host: " + "; ".join(reasons))


def powershell_is_available() -> bool:
    """Observe the PowerShell interpreter itself, never a command's outcome."""

    return shutil.which("powershell") is not None


def _require_powershell() -> str:
    if not powershell_is_available():
        pytest.skip(POWERSHELL_SKIP_REASON)
    return "powershell"


class PostSupportSkipAttempted(AssertionError):
    """A skip was attempted after environment support had already passed.

    Once the support predicate passes, a skip can only be hiding a real product
    regression, so it is converted into a failure rather than into a green
    selection with the load-bearing tests skipped.
    """


@contextlib.contextmanager
def forbid_skip(label: str):
    """Run a region in which every skip attempt becomes a test failure."""

    skipped = pytest.skip.Exception
    saved = (pytest.skip, pytest.xfail, pytest.importorskip)

    def _refuse(*_arguments, **_keywords):
        raise PostSupportSkipAttempted(
            f"{label} attempted to skip after environment support passed"
        )

    pytest.skip = _refuse
    pytest.xfail = _refuse
    pytest.importorskip = _refuse
    try:
        yield
    except skipped as attempted:
        raise PostSupportSkipAttempted(
            f"{label} raised a skip outcome after environment support passed: "
            f"{attempted!s:.200}"
        ) from attempted
    finally:
        pytest.skip, pytest.xfail, pytest.importorskip = saved


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
        # Genuine-restart identity, captured while the child is still alive so
        # a later assertion never has to trust a reused Python object.
        self.pid: int | None = None
        self.process_object_id: int | None = None
        self.ready_at: float | None = None
        self.closed_at: float | None = None
        self.exit_code: int | None = None
        # Exactly the headers this launcher's transport really put on the wire.
        self.sent_headers: list[dict] = []

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
        self.pid = self.process.pid
        self.process_object_id = id(self.process)
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
        self.ready_at = time.monotonic()
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
        self.exit_code = process.poll()
        self.closed_at = time.monotonic()

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
        self.sent_headers.append({"path": path, **headers})
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


def _provider_invocation_guard(base: Path) -> tuple[Path, Path]:
    """Install an audit hook recording every child process the product starts.

    The hook is the provider-invocation counter: the wrapper-chain attestation
    is allowed to run its discovery probes, but a genuine provider invocation
    would have to start ``node.exe`` or a ``cursor-agent`` launcher, and every
    such start is recorded here.
    """

    guard = base / "providerguard"
    guard.mkdir(exist_ok=True)
    (guard / "sitecustomize.py").write_text(
        "import atexit, os, sys\n"
        "_log = os.environ.get('ADMISSIBLE_PROVIDER_AUDIT_LOG', '')\n"
        "_events = []\n"
        "_state = {'recording': True}\n"
        "def _hook(event, args):\n"
        "    if not _state['recording'] or event != 'subprocess.Popen':\n"
        "        return\n"
        "    try:\n"
        "        executable, argv = args[0], args[1]\n"
        "        first = executable\n"
        "        if first is None and argv:\n"
        "            first = argv[0] if not isinstance(argv, (str, bytes)) else argv\n"
        "        text = '' if first is None else os.fsdecode(first)\n"
        "    except Exception:\n"
        "        text = '<unreadable>'\n"
        "    _events.append(text)\n"
        "sys.addaudithook(_hook)\n"
        "def _flush():\n"
        "    _state['recording'] = False\n"
        "    if _log:\n"
        "        with open(_log, 'w', encoding='utf-8') as handle:\n"
        "            handle.write('\\n'.join(_events))\n"
        "atexit.register(_flush)\n",
        encoding="utf-8",
    )
    return guard, base / "provider-audit.txt"


def _count_provider_invocations(started: tuple[str, ...]) -> int:
    """Count child starts that would be a real provider invocation."""

    invocations = 0
    for entry in started:
        stem = ntpath.splitext(ntpath.basename(entry))[0].casefold()
        if stem == "node" or stem.startswith("cursor-agent"):
            invocations += 1
    return invocations


def _acquire_real_wrapper(installation, source, contract, base: Path):
    """Invoke the product's own preflight-only child.

    This function performs the invocation and nothing else.  It classifies
    nothing, decides nothing about host support, and never skips: interpreting
    what came back belongs to :func:`validate_wrapper_acquisition`.
    """

    runs = base / "wrapper-runs"
    runs.mkdir()
    run_root = runs / contract.generated["run_id"]
    guard, audit_log = _provider_invocation_guard(base)
    argv = [
        str(installation.python),
        "-m",
        "admissible.product_launcher.preflight_runner",
        "--source-repository", str(source.path),
        "--required-source-head", source.head,
        "--run-root", str(run_root),
        "--run-id", contract.generated["run_id"],
        "--session-id", contract.generated["session_id"],
        "--executable", CURSOR_DISCOVERY_COMMAND,
        "--profile-document", str(contract.document),
        "--attestation-class", "wrapper-chain",
    ]
    invocation_error: BaseException | None = None
    completed = None
    try:
        completed = _run(
            argv,
            cwd=base,
            timeout=900,
            env={
                "PYTHONPATH": str(guard),
                "ADMISSIBLE_PROVIDER_AUDIT_LOG": str(audit_log),
            },
        )
    except (OSError, subprocess.SubprocessError) as failure:
        # Recorded, never classified here: an invocation fault is a product
        # observation the validator must turn into a failure.
        invocation_error = failure
    wrapper = base / "wrapper.json"
    wrapper.write_bytes(b"" if completed is None else completed.stdout)
    started = tuple(
        line
        for line in (
            audit_log.read_text(encoding="utf-8").splitlines()
            if audit_log.exists()
            else []
        )
        if line
    )
    return SimpleNamespace(
        path=wrapper,
        argv=argv,
        returncode=None if completed is None else completed.returncode,
        stdout=b"" if completed is None else completed.stdout,
        stderr=b"" if completed is None else completed.stderr,
        run_root=run_root,
        invocation_error=invocation_error,
        started_children=started,
        provider_invocations=_count_provider_invocations(started),
    )


def validate_wrapper_acquisition(acquired) -> SimpleNamespace:
    """Classify one already-completed wrapper acquisition, failing closed.

    Every unexpected condition raises ``AssertionError``.  This function
    deliberately contains no ``pytest.skip``, ``pytest.xfail`` or
    ``pytest.importorskip`` call and catches no broad exception: after the
    environment-support predicate has passed, a nonzero return code, malformed
    stdout, a created run root, an invocation fault, or any provider invocation
    is a product regression, not an unsupported host.
    """

    assert acquired.invocation_error is None, (
        "the installed preflight child could not be invoked at all: "
        f"{acquired.invocation_error!r}"
    )
    code = acquired.returncode
    assert code is not None, "the installed preflight child produced no exit code"
    if code == PREFLIGHT_INTERNAL_EXIT:
        raise AssertionError(
            "the installed preflight child returned "
            f"{PREFLIGHT_INTERNAL_EXIT} (internal fault); this is a product "
            "regression, not an unsupported host: "
            f"{_bounded_diagnostic(acquired.stderr)!r}"
        )
    if code == PREFLIGHT_CLI_CONTRACT_EXIT:
        raise AssertionError(
            "the installed preflight child returned "
            f"{PREFLIGHT_CLI_CONTRACT_EXIT} (CLI contract violation); the "
            "committed argv no longer matches the installed command surface: "
            f"{_bounded_diagnostic(acquired.stderr)!r}"
        )
    if code == PREFLIGHT_ARGPARSE_EXIT:
        raise AssertionError(
            f"the installed preflight child returned {PREFLIGHT_ARGPARSE_EXIT} "
            "(argument parsing failure): "
            f"{_bounded_diagnostic(acquired.stderr)!r}"
        )
    assert code == 0, (
        f"the installed preflight child returned {code}: "
        f"{_bounded_diagnostic(acquired.stderr)!r}"
    )
    assert acquired.stdout, "the installed preflight child printed no envelope"
    try:
        envelope = json.loads(acquired.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as malformed:
        raise AssertionError(
            "the installed preflight child printed malformed wrapper stdout: "
            f"{malformed!s:.200}"
        ) from malformed
    assert isinstance(envelope, dict), "the wrapper envelope is not a JSON object"
    status = envelope.get("status")
    assert status == "PREFLIGHT_READY", (
        f"the wrapper status is {status!r} rather than PREFLIGHT_READY: "
        f"{_bounded_diagnostic(acquired.stderr)!r}"
    )
    attestation = envelope.get("attestation")
    assert isinstance(attestation, dict), "the wrapper carries no attestation"
    observed_class = attestation.get("attestation_class")
    assert observed_class == ATTESTATION_CLASS_WRAPPER_CHAIN, (
        f"the observed wrapper family is {observed_class!r} rather than the "
        f"expected {ATTESTATION_CLASS_WRAPPER_CHAIN}"
    )
    assert "authorization_payload" in envelope, (
        "the wrapper envelope carries no authorization payload"
    )
    assert acquired.provider_invocations == 0, (
        "the provider-free wrapper acquisition started "
        f"{acquired.provider_invocations} provider process(es): "
        f"{acquired.started_children[:8]}"
    )
    assert not acquired.run_root.exists(), (
        "preflight-only wrapper acquisition created a run root at "
        f"{acquired.run_root}"
    )
    return SimpleNamespace(
        real_path_executed=True,
        substituted=False,
        returncode=code,
        status=status,
        attestation_class=observed_class,
        provider_invocations=acquired.provider_invocations,
        run_root_created=False,
        started_children=acquired.started_children,
        envelope=envelope,
    )


@pytest.fixture(scope="session")
def real_wrapper_acquisition(tmp_path_factory):
    """Build the isolated installation and acquire one real wrapper, once.

    The support decision lives here and is taken *before* any product process
    starts.  Everything after it runs inside :func:`forbid_skip`, so no product
    outcome can be downgraded into an unsupported-environment skip.
    """

    _require_supported_operator_host()
    reasons = classify_operator_host_support()

    with forbid_skip("real wrapper acquisition"):
        base = _require_external_root(tmp_path_factory)
        installation = _build_isolated_installation(base)
        source = _external_source_repository(base)
        contract = _author_real_contract(installation, source, base)
        acquired = _acquire_real_wrapper(installation, source, contract, base)
        witness = validate_wrapper_acquisition(acquired)
    return SimpleNamespace(
        base=base,
        installation=installation,
        source=source,
        contract=contract,
        wrapper=acquired,
        witness=witness,
        support_reasons=reasons,
    )


@pytest.fixture(scope="session")
def workflow(real_wrapper_acquisition):
    """Execute the complete installed operator workflow exactly once."""

    with forbid_skip("the installed operator workflow"):
        return _installed_operator_workflow(real_wrapper_acquisition)


def _installed_operator_workflow(acquisition) -> SimpleNamespace:
    base = acquisition.base
    installation = acquisition.installation
    source = acquisition.source
    contract = acquisition.contract
    wrapper = acquisition.wrapper

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
        acquisition=acquisition,
        witness=acquisition.witness,
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


class OperationJournal:
    """The exact ordered operations one exported message really went through."""

    def __init__(self) -> None:
        self.events: list[str] = []

    def record(self, event: str) -> None:
        assert event in PUBLIC_MESSAGE_VERIFICATION_ORDER, event
        self.events.append(event)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"OperationJournal({self.events!r})"


class ExportedMessageIntegrityError(AssertionError):
    """One refused public confirmation-message export.

    Raising this means the installed tag helper was never started and the
    operator-selected message file was never written.
    """


def verify_exported_confirmation_message(review, *, journal=None) -> bytes:
    """Verify the public confirmation-message export and return exact bytes.

    The checks run in exactly one order -- read, strict decode, declared length,
    declared SHA-256, accepted domain prefix, single NUL framing boundary, then
    equality against the accepted public-message construction rebuilt by the
    product's own primitive.  Nothing here repairs declared metadata, replaces
    exported bytes, reconstructs a file, adds the domain, or adds the separator:
    the oracle only compares.
    """

    record = journal.record if journal is not None else (lambda _event: None)

    identity = review["pairing_identity"]
    encoded = identity["confirmation_message_base64"]
    if not isinstance(encoded, str):
        raise ExportedMessageIntegrityError(
            f"the public Base64 export is {type(encoded).__name__}, not a string"
        )
    record("PUBLIC_EXPORT_READ")

    try:
        message = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as malformed:
        raise ExportedMessageIntegrityError(
            f"strict Base64 decoding refused the public export: {malformed!s:.120}"
        ) from malformed
    record("STRICT_BASE64_DECODE")

    declared_length = identity["confirmation_message_byte_length"]
    if not isinstance(declared_length, int) or isinstance(declared_length, bool):
        raise ExportedMessageIntegrityError(
            "the declared confirmation-message byte length is not an integer"
        )
    if len(message) != declared_length:
        raise ExportedMessageIntegrityError(
            f"decoded {len(message)} bytes against a declared length of "
            f"{declared_length}"
        )
    record("LENGTH_VERIFIED")

    declared_sha256 = identity["confirmation_message_sha256"]
    observed_sha256 = hashlib.sha256(message).hexdigest()
    if not isinstance(declared_sha256, str) or observed_sha256 != declared_sha256:
        raise ExportedMessageIntegrityError(
            "the exported bytes do not match the declared SHA-256"
        )
    record("SHA256_VERIFIED")

    prefix = (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
        + HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR
    )
    if not message.startswith(prefix):
        raise ExportedMessageIntegrityError(
            "the exported bytes do not start with the accepted domain prefix"
        )
    record("DOMAIN_VERIFIED")

    separator_index = len(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN)
    if (
        message.count(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR) != 1
        or message[separator_index : separator_index + 1]
        != HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR
    ):
        raise ExportedMessageIntegrityError(
            "the exported bytes do not carry exactly one NUL framing boundary "
            "immediately after the domain constant"
        )
    record("NUL_BOUNDARY_VERIFIED")

    try:
        authority_document = json.loads(message[len(prefix) :].decode("utf-8"))
        authority = HistoricalEvaluationPairingAuthority.from_dict(
            authority_document
        ).validated()
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as bad:
        raise ExportedMessageIntegrityError(
            f"the framed tail is not one canonical pairing authority: {bad!s:.160}"
        ) from bad
    accepted = build_historical_pairing_confirmation_message(
        pairing_authority=authority
    )
    if accepted != message:
        raise ExportedMessageIntegrityError(
            "the exported bytes differ from the accepted public-message "
            "construction for the authority they carry"
        )
    record("ORACLE_EQUALITY_VERIFIED")
    return message


def export_verified_message_and_tag(review, message_file: Path, *, runner, journal):
    """Verify, then write, then start the installed helper -- in that order.

    The helper call is physically downstream of every integrity and framing
    check, so a refused export can never reach it.
    """

    message = verify_exported_confirmation_message(review, journal=journal)
    with open(message_file, "wb") as handle:
        handle.write(message)
    journal.record("MESSAGE_FILE_WRITTEN")
    journal.record("INSTALLED_TAG_HELPER_STARTED")
    return message, runner(message_file)


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
    return SimpleNamespace(
        csrf=csrf,
        prepared=prepared,
        identity=identity,
        review=review,
        preparation_id=preparation_id,
        authority_fingerprint=authority_fingerprint,
        message=None,
        message_file=base / f"confirmation-message-{index}.bin",
        journal=OperationJournal(),
    )


def _tag_runner(installation, secret_file: Path):
    """Return a callable that starts the installed tag helper on a file."""

    def _start(message_file: Path):
        return _run(
            [
                str(installation.scripts / "admissible-historical-pairing-tag"),
                "--message-file", str(message_file),
                "--secret-file", str(secret_file),
            ],
            cwd=installation.venv,
        )

    return _start


def _tag_from_helper_stdout(completed) -> str:
    """Parse the submitted credential directly out of installed helper stdout.

    There is no fallback: no in-process HMAC, no oracle value, and no repair.
    A helper that did not print exactly one lowercase 64-hex line fails here.
    """

    assert completed.returncode == 0, _bounded_diagnostic(completed.stderr)
    assert completed.stderr == b"", _bounded_diagnostic(completed.stderr)
    raw = completed.stdout
    terminator = os.linesep.encode("ascii")
    assert raw.endswith(terminator), repr(raw[-16:])
    text = raw[: -len(terminator)].decode("ascii")
    # Diagnostics never carry the credential itself, only its shape.
    assert len(text) == 64, len(text)
    assert all(
        character in "0123456789abcdef" for character in text
    ), "the installed helper printed a non-lowercase-hex credential"
    return text


def _export_and_tag(installation, exported, secret_file: Path):
    """Run the complete accepted export boundary for one preparation."""

    message, completed = export_verified_message_and_tag(
        exported.review,
        exported.message_file,
        runner=_tag_runner(installation, secret_file),
        journal=exported.journal,
    )
    exported.message = message
    return completed


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
        launcher_object_id=None,
        process_object_id=None,
        pid=None,
        argv0="",
        ready_at=None,
        closed_at=None,
        exit_code=None,
        sent_headers=[],
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
        launcher_object_id=None,
        process_object_id=None,
        pid=None,
        argv0="",
        ready_at=None,
        closed_at=None,
        exit_code=None,
        sent_headers=[],
        stdout=b"" if refused is None else refused.stdout,
        stderr=b"" if refused is None else refused.stderr,
        payload_status=None,
        payload_body=None,
        old_review=(None, {}),
        old_confirm=(None, {}),
        first_terminated_before_second_start=False,
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
        tagged = _export_and_tag(installation, exported, secret_file)
        # The submitted credential is parsed out of installed helper stdout and
        # from nothing else; the in-process oracle only ever compares.
        tag = _tag_from_helper_stdout(tagged)
        exported.journal.record("CONFIRMATION_SUBMITTED")
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
        launcher_object_id=id(launcher),
        process_object_id=launcher.process_object_id,
        pid=launcher.pid,
        argv0=launcher.argv[0],
        ready_at=launcher.ready_at,
        closed_at=launcher.closed_at,
        exit_code=launcher.exit_code,
        sent_headers=list(launcher.sent_headers),
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
    """Independent preparations, each refused through one real request."""

    controls = {}

    wrong = _prepare_and_export(launcher, base, ".wrongtag", index=1)
    _export_and_tag(installation, wrong, secret_file)
    wrong.journal.record("CONFIRMATION_SUBMITTED")
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
    upper_tag = _tag_from_helper_stdout(
        _export_and_tag(installation, upper, secret_file)
    )
    upper.journal.record("CONFIRMATION_SUBMITTED")
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

    # One character of the installed helper's own stdout is flipped.  If the
    # submitted credential were anything other than exactly what the helper
    # printed, this request could not be distinguished from the accepted one.
    mutated = _prepare_and_export(launcher, base, ".mutatedstdout", index=7)
    mutated_source = _tag_from_helper_stdout(
        _export_and_tag(installation, mutated, secret_file)
    )
    flipped = ("1" if mutated_source[0] == "0" else "0") + mutated_source[1:]
    assert flipped != mutated_source
    mutated.journal.record("CONFIRMATION_SUBMITTED")
    controls["mutated_helper_stdout"] = SimpleNamespace(
        exported=mutated,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{mutated.preparation_id}/confirmation",
            body={"expected_authority_fingerprint": mutated.authority_fingerprint},
            extra={CSRF_HEADER: mutated.csrf, CONFIRMATION_HEADER: flipped},
        ),
    )

    # The helper is run against a different secret file, so its stdout differs
    # from the in-process oracle value for the very same authority.  What is
    # submitted is the helper's value, and it is refused.
    foreign_secret = base / "foreign-secret.bin"
    with open(foreign_secret, "wb") as handle:
        handle.write(bytes((byte ^ 0x5A) for byte in SECRET_BYTES))
    foreign = _prepare_and_export(launcher, base, ".foreignsecret", index=8)
    foreign_tag = _tag_from_helper_stdout(
        _export_and_tag(installation, foreign, foreign_secret)
    )
    foreign.journal.record("CONFIRMATION_SUBMITTED")
    controls["foreign_secret_helper_tag"] = SimpleNamespace(
        exported=foreign,
        helper_tag=foreign_tag,
        response=launcher.json_call(
            "POST",
            f"{PREPARATIONS_ROUTE}/{foreign.preparation_id}/confirmation",
            body={"expected_authority_fingerprint": foreign.authority_fingerprint},
            extra={CSRF_HEADER: foreign.csrf, CONFIRMATION_HEADER: foreign_tag},
        ),
    )

    authorization = _prepare_and_export(launcher, base, ".authheader", index=3)
    authorization_tag = _tag_from_helper_stdout(
        _export_and_tag(installation, authorization, secret_file)
    )
    authorization.journal.record("CONFIRMATION_SUBMITTED")
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
    body_tag = _tag_from_helper_stdout(
        _export_and_tag(installation, body_channel, secret_file)
    )
    body_channel.journal.record("CONFIRMATION_SUBMITTED")
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
    stale_tag = _tag_from_helper_stdout(
        _export_and_tag(installation, stale, secret_file)
    )
    stale.journal.record("CONFIRMATION_SUBMITTED")
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
    # The first launcher must already be a terminated process before the second
    # one is even constructed, so readiness below can only come from a new child.
    first_terminated_before_second_start = (
        first.exit_code is not None and first.closed_at is not None
    )
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
        tagged = _export_and_tag(installation, replayed, secret_file)
        tag = _tag_from_helper_stdout(tagged)
        replayed.journal.record("CONFIRMATION_SUBMITTED")
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
        launcher_object_id=id(launcher),
        process_object_id=launcher.process_object_id,
        pid=launcher.pid,
        argv0=launcher.argv[0],
        ready_at=launcher.ready_at,
        closed_at=launcher.closed_at,
        exit_code=launcher.exit_code,
        sent_headers=list(launcher.sent_headers),
        first_terminated_before_second_start=first_terminated_before_second_start,
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
# A. Environment-support classification and the skip policy itself.
# ---------------------------------------------------------------------------


# Every skipped report this module produced, recorded by a real pytest hook so
# the final supported-host selection can be proven to contain no skip at all.
SKIP_LEDGER: list[tuple[str, str, str]] = []


def pytest_runtest_logreport(report):  # pragma: no cover - pytest hook
    if report.skipped and MODULE_PATH.name in report.nodeid:
        SKIP_LEDGER.append((report.nodeid, report.when, str(report.longrepr)))


@pytest.fixture(scope="session", autouse=True)
def _skip_ledger(request):
    """Register this module as a plugin so its own skips are observable."""

    manager = request.config.pluginmanager
    name = "historical-pairing-operator-skip-ledger"
    if not manager.has_plugin(name):
        manager.register(sys.modules[__name__], name)
        request.addfinalizer(lambda: manager.unregister(name=name))
    return SKIP_LEDGER


def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def _named_function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} is not defined in this module")


def _is_skip_call(child) -> bool:
    if not isinstance(child, ast.Call):
        return False
    target = child.func
    return (
        isinstance(target, ast.Attribute)
        and target.attr in {"skip", "xfail", "importorskip"}
        and isinstance(target.value, ast.Name)
        and target.value.id == "pytest"
    )


def _skip_calls(node) -> list[ast.Call]:
    """Every ``pytest.skip``/``xfail``/``importorskip`` call inside *node*."""

    return [child for child in ast.walk(node) if _is_skip_call(child)]


def _outside_nested_functions(node):
    """Walk *node* without descending into any nested function definition."""

    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield child
        yield from _outside_nested_functions(child)


def _own_skip_calls(function: ast.FunctionDef) -> list[ast.Call]:
    """Skip calls this function makes itself, not ones a nested helper makes."""

    return [child for child in _outside_nested_functions(function) if _is_skip_call(child)]


def _code_only(function: ast.FunctionDef) -> str:
    """Render a function without its docstring, so prose cannot be scanned."""

    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if not body:  # pragma: no cover - defensive
        return ""
    rendered = ast.Module(body=body, type_ignores=[])
    return ast.unparse(rendered)


def _identifiers(node) -> set[str]:
    """Every name and attribute this code really touches, prose excluded."""

    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _line_span(function: ast.FunctionDef) -> range:
    return range(function.lineno, (function.end_lineno or function.lineno) + 1)


def _synthetic_envelope() -> dict:
    """The minimal accepted wrapper envelope shape, for fault injection only."""

    return {
        "status": "PREFLIGHT_READY",
        "authorization_payload": {"payload_fingerprint": "0" * 64},
        "attestation": {"attestation_class": ATTESTATION_CLASS_WRAPPER_CHAIN},
        "where_diagnostic": {},
        "durability_capability": {},
    }


def _synthetic_acquisition(tmp_path: Path, **overrides) -> SimpleNamespace:
    envelope = overrides.pop("envelope", _synthetic_envelope())
    stdout = overrides.pop(
        "stdout", json.dumps(envelope, sort_keys=True).encode("utf-8")
    )
    fields = {
        "path": tmp_path / "wrapper.json",
        "argv": ["python", "-m", "admissible.product_launcher.preflight_runner"],
        "returncode": 0,
        "stdout": stdout,
        "stderr": b"",
        "run_root": tmp_path / "runs" / "run-0001",
        "invocation_error": None,
        "started_children": ("C:\\Windows\\System32\\where.exe",),
        "provider_invocations": 0,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_supported_host_executed_the_real_wrapper_acquisition_path(
    real_wrapper_acquisition,
):
    """The one positive witness that the real provider-free path really ran.

    It depends on the acquisition fixture alone, so it survives even if the
    downstream complete-workflow fixture were to disappear or skip.
    """

    acquisition = real_wrapper_acquisition
    witness = acquisition.witness
    assert acquisition.support_reasons == ()
    assert witness.real_path_executed is True
    assert witness.substituted is False
    assert acquisition.wrapper.invocation_error is None
    assert witness.returncode == 0
    assert witness.status == "PREFLIGHT_READY"
    assert witness.attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN
    assert witness.provider_invocations == 0
    assert witness.run_root_created is False
    assert not acquisition.wrapper.run_root.exists()
    # The audit hook really observed the acquisition, so a zero provider count
    # is a positive observation rather than a blind one.
    assert acquisition.wrapper.started_children, (
        "the provider-invocation audit recorded no child process at all"
    )
    # The complete E2E fixture is the real one, not a substitute: it is still
    # defined here and still executes the complete installed workflow.
    text = MODULE_PATH.read_text(encoding="utf-8")
    tree = _module_tree()
    complete = _named_function(tree, "workflow")
    assert "_installed_operator_workflow" in (
        ast.get_source_segment(text, complete) or ""
    )
    assert _skip_calls(_named_function(tree, "_installed_operator_workflow")) == []


def test_environment_support_is_decided_from_observed_prerequisites_only():
    reasons = classify_operator_host_support()
    if os.name == "nt" and shutil.which("git") and shutil.which("tar"):
        assert reasons == () or all("cursor-agent" in item for item in reasons)
    classifier = _named_function(_module_tree(), "classify_operator_host_support")
    touched = _identifiers(classifier)
    for forbidden in (
        "returncode",
        "stdout",
        "stderr",
        "exit_code",
        "wrapper",
        "acquired",
        "envelope",
        "validate_wrapper_acquisition",
        "_acquire_real_wrapper",
    ):
        assert forbidden not in touched, forbidden
    # It observes prerequisites and starts no product process of its own.
    assert touched & {"which", "environ", "name"}, touched
    assert "run" not in touched and "Popen" not in touched


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"returncode": PREFLIGHT_INTERNAL_EXIT, "stdout": b""}, "67"),
        ({"returncode": PREFLIGHT_CLI_CONTRACT_EXIT, "stdout": b""}, "64"),
        ({"returncode": PREFLIGHT_ARGPARSE_EXIT, "stdout": b""}, "2"),
        ({"returncode": 3, "stdout": b""}, "returned 3"),
        ({"returncode": None}, "no exit code"),
        ({"stdout": b"not json at all"}, "malformed wrapper stdout"),
        ({"stdout": b""}, "printed no envelope"),
        ({"provider_invocations": 1}, "provider process"),
    ],
)
def test_injected_wrapper_faults_become_test_failures(tmp_path, overrides, expected):
    acquired = _synthetic_acquisition(tmp_path, **overrides)
    with pytest.raises(AssertionError) as caught:
        validate_wrapper_acquisition(acquired)
    assert expected in str(caught.value)


def test_injected_invocation_exception_becomes_a_test_failure(tmp_path):
    acquired = _synthetic_acquisition(
        tmp_path, invocation_error=OSError("spawn refused")
    )
    with pytest.raises(AssertionError) as caught:
        validate_wrapper_acquisition(acquired)
    assert "could not be invoked" in str(caught.value)


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ({"status": "PREFLIGHT_BLOCKED"}, "PREFLIGHT_READY"),
        ({"attestation": {"attestation_class": "LOCAL_PACKAGE_BIN"}}, "wrapper family"),
        ({"attestation": "not-a-mapping"}, "no attestation"),
    ],
)
def test_injected_wrapper_schema_regressions_become_test_failures(
    tmp_path, mutation, expected
):
    envelope = {**_synthetic_envelope(), **mutation}
    acquired = _synthetic_acquisition(tmp_path, envelope=envelope)
    with pytest.raises(AssertionError) as caught:
        validate_wrapper_acquisition(acquired)
    assert expected in str(caught.value)


def test_a_product_refusal_that_created_a_run_root_becomes_a_test_failure(tmp_path):
    acquired = _synthetic_acquisition(tmp_path)
    acquired.run_root.mkdir(parents=True)
    with pytest.raises(AssertionError) as caught:
        validate_wrapper_acquisition(acquired)
    assert "created a run root" in str(caught.value)


def test_a_forced_post_support_skip_attempt_becomes_a_test_failure():
    def _post_support_region():
        pytest.skip("this must never be reachable after support has passed")

    with pytest.raises(PostSupportSkipAttempted):
        with forbid_skip("probe"):
            _post_support_region()
    # The guard restores the real outcome API afterwards.
    assert pytest.skip is not None and hasattr(pytest.skip, "Exception")
    skipped = pytest.skip.Exception

    def _raises_the_outcome_directly():
        raise skipped("smuggled skip outcome")

    with pytest.raises(PostSupportSkipAttempted):
        with forbid_skip("probe"):
            _raises_the_outcome_directly()

    def _broad_handler_converting_to_skip():
        try:
            raise RuntimeError("an arbitrary workflow exception")
        except Exception:
            pytest.skip("broadened environment skip")

    with pytest.raises(PostSupportSkipAttempted):
        with forbid_skip("probe"):
            _broad_handler_converting_to_skip()


def _behavioural_skip_probe_span(tree: ast.Module) -> range:
    """Line span of the one test that deliberately provokes skip attempts."""

    return _line_span(
        _named_function(
            tree, "test_a_forced_post_support_skip_attempt_becomes_a_test_failure"
        )
    )


def test_wrapper_result_validation_contains_no_skip_of_any_kind():
    text = MODULE_PATH.read_text(encoding="utf-8")
    validator = _named_function(_module_tree(), "validate_wrapper_acquisition")
    assert _skip_calls(validator) == []
    code = _code_only(validator)
    for forbidden in ("pytest.skip", "pytest.xfail", "pytest.importorskip"):
        assert forbidden not in code, forbidden
    # Unknown conditions fail closed rather than being swallowed.
    for handler in (
        node for node in ast.walk(validator) if isinstance(node, ast.ExceptHandler)
    ):
        assert handler.type is not None, "validation must not use a bare except"
        caught = ast.get_source_segment(text, handler.type) or ""
        assert not re.search(r"Exception|BaseException", caught), caught


def test_no_skip_is_conditioned_on_a_product_return_code():
    text = MODULE_PATH.read_text(encoding="utf-8")
    tree = _module_tree()
    probe = _behavioural_skip_probe_span(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or node.lineno in probe:
            continue
        condition = ast.get_source_segment(text, node.test) or ""
        if "returncode" not in condition and "exit_code" not in condition:
            continue
        for statement in node.body + node.orelse:
            assert _skip_calls(statement) == [], condition


def test_no_broad_exception_handler_ends_in_a_skip():
    text = MODULE_PATH.read_text(encoding="utf-8")
    tree = _module_tree()
    probe = _behavioural_skip_probe_span(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.lineno in probe:
            continue
        assert _skip_calls(node) == [], (
            ast.get_source_segment(text, node) or ""
        )[:200]


def test_every_skip_call_site_is_an_approved_pre_invocation_predicate():
    approved = {"_require_powershell", "_require_supported_operator_host"}
    tree = _module_tree()
    probe = _behavioural_skip_probe_span(tree)
    observed = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.lineno not in probe
        and _own_skip_calls(node)
    }
    assert observed == approved, observed
    # Both approved predicates observe a prerequisite and nothing else.
    for name in sorted(approved):
        function = _named_function(tree, name)
        touched = _identifiers(function)
        for forbidden in ("returncode", "stdout", "stderr", "exit_code", "acquired"):
            assert forbidden not in touched, (name, forbidden)
        assert not [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.ExceptHandler)
        ], name


def test_environment_support_is_decided_before_the_wrapper_is_invoked():
    tree = _module_tree()
    gate = _code_only(_named_function(tree, "_require_supported_operator_host"))
    assert "classify_operator_host_support" in gate
    fixture = _named_function(tree, "real_wrapper_acquisition")
    required = invoked = None
    for node in ast.walk(fixture):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id == "_require_supported_operator_host":
            required = node.lineno
        if node.func.id == "_acquire_real_wrapper":
            invoked = node.lineno
    assert required is not None and invoked is not None
    assert required < invoked, (required, invoked)
    # The support decision is the only thing that may precede the guard.
    body = _code_only(fixture)
    assert body.index("_require_supported_operator_host") < body.index("forbid_skip")
    assert body.index("forbid_skip") < body.index("_acquire_real_wrapper")


def test_the_workflow_fixture_runs_entirely_inside_the_no_skip_guard():
    fixture = _named_function(_module_tree(), "workflow")
    body = _code_only(fixture)
    assert "with forbid_skip(" in body
    assert _skip_calls(fixture) == []


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


def _reframed_review(review: dict, raw: bytes) -> dict:
    """Re-declare the public export over *raw*, keeping the metadata honest."""

    identity = dict(review["pairing_identity"])
    identity["confirmation_message_base64"] = base64.b64encode(raw).decode("ascii")
    identity["confirmation_message_byte_length"] = len(raw)
    identity["confirmation_message_sha256"] = hashlib.sha256(raw).hexdigest()
    return {**review, "pairing_identity": identity}


def _relabelled_review(review: dict, **overrides) -> dict:
    identity = {**review["pairing_identity"], **overrides}
    return {**review, "pairing_identity": identity}


# Every corruption of the public export that must be refused before the
# installed tag helper is allowed to start.
CORRUPTED_EXPORTS = (
    "malformed_base64",
    "whitespace_polluted_base64",
    "declared_length_too_small",
    "declared_length_too_large",
    "wrong_sha256",
    "wrong_domain",
    "missing_nul",
    "extra_framing_prefix",
    "bytes_differ_from_accepted_authority",
)


def _corruptions(message: bytes) -> dict:
    """Every refused public export, with the stage that must refuse it."""

    prefix = (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
        + HISTORICAL_PAIRING_CONFIRMATION_DOMAIN_SEPARATOR
    )
    encoded = base64.b64encode(message).decode("ascii")
    half = len(encoded) // 2
    tail = json.loads(message[len(prefix):].decode("utf-8"))
    return {
        "malformed_base64": (
            lambda review: _relabelled_review(
                review, confirmation_message_base64=encoded[:half] + "!!" + encoded[half:]
            ),
            "PUBLIC_EXPORT_READ",
        ),
        "whitespace_polluted_base64": (
            lambda review: _relabelled_review(
                review, confirmation_message_base64=encoded[:half] + "\n " + encoded[half:]
            ),
            "PUBLIC_EXPORT_READ",
        ),
        "declared_length_too_small": (
            lambda review: _relabelled_review(
                review, confirmation_message_byte_length=len(message) - 1
            ),
            "STRICT_BASE64_DECODE",
        ),
        "declared_length_too_large": (
            lambda review: _relabelled_review(
                review, confirmation_message_byte_length=len(message) + 1
            ),
            "STRICT_BASE64_DECODE",
        ),
        "wrong_sha256": (
            lambda review: _relabelled_review(
                review,
                confirmation_message_sha256=("f" * 64)
                if review["pairing_identity"]["confirmation_message_sha256"][0] != "f"
                else ("0" * 64),
            ),
            "LENGTH_VERIFIED",
        ),
        "wrong_domain": (
            lambda review: _reframed_review(
                review, b"x" + message[1:]
            ),
            "SHA256_VERIFIED",
        ),
        "missing_nul": (
            lambda review: _reframed_review(
                review,
                HISTORICAL_PAIRING_CONFIRMATION_DOMAIN
                + message[len(prefix):],
            ),
            "SHA256_VERIFIED",
        ),
        "extra_framing_prefix": (
            lambda review: _reframed_review(review, prefix + message),
            "DOMAIN_VERIFIED",
        ),
        "bytes_differ_from_accepted_authority": (
            lambda review: _reframed_review(
                review,
                prefix
                + json.dumps(tail, sort_keys=True, indent=1).encode("utf-8"),
            ),
            "NUL_BOUNDARY_VERIFIED",
        ),
    }


class _HelperSpy:
    """A stand-in for the installed helper that records every start."""

    def __init__(self) -> None:
        self.started: list[Path] = []

    def __call__(self, message_file: Path):  # pragma: no cover - must never run
        self.started.append(message_file)
        raise AssertionError(
            "the installed tag helper was started for a refused export"
        )


def test_public_message_verification_ran_in_exactly_the_required_order(workflow):
    assert workflow.session.exported.journal.events == list(
        PUBLIC_MESSAGE_VERIFICATION_ORDER
    )
    assert workflow.restart.replayed.journal.events == list(
        PUBLIC_MESSAGE_VERIFICATION_ORDER
    )
    for name, control in workflow.session.negatives.items():
        assert control.exported.journal.events == list(
            PUBLIC_MESSAGE_VERIFICATION_ORDER
        ), name


def test_message_file_handed_to_the_helper_holds_only_verified_bytes(workflow):
    exported = workflow.session.exported
    assert exported.message_file.read_bytes() == exported.message
    assert exported.message == verify_exported_confirmation_message(exported.review)
    events = exported.journal.events
    assert events.index("MESSAGE_FILE_WRITTEN") < events.index(
        "INSTALLED_TAG_HELPER_STARTED"
    )
    for stage in (
        "LENGTH_VERIFIED",
        "SHA256_VERIFIED",
        "DOMAIN_VERIFIED",
        "NUL_BOUNDARY_VERIFIED",
        "ORACLE_EQUALITY_VERIFIED",
    ):
        assert events.index(stage) < events.index("MESSAGE_FILE_WRITTEN"), stage


@pytest.mark.parametrize("corruption", CORRUPTED_EXPORTS)
def test_every_corrupted_export_is_refused_before_the_helper_starts(
    workflow, tmp_path, corruption
):
    exported = workflow.session.exported
    catalogue = _corruptions(exported.message)
    assert tuple(catalogue) == CORRUPTED_EXPORTS
    corrupt, expected_last_stage = catalogue[corruption]
    review = corrupt(exported.review)
    journal = OperationJournal()
    spy = _HelperSpy()
    message_file = tmp_path / f"{corruption}.bin"
    with pytest.raises(ExportedMessageIntegrityError):
        export_verified_message_and_tag(
            review, message_file, runner=spy, journal=journal
        )
    assert spy.started == [], corruption
    assert not message_file.exists(), corruption
    assert "MESSAGE_FILE_WRITTEN" not in journal.events
    assert "INSTALLED_TAG_HELPER_STARTED" not in journal.events
    assert journal.events and journal.events[-1] == expected_last_stage, journal.events


def test_the_oracle_only_compares_and_never_repairs_the_export():
    text = MODULE_PATH.read_text(encoding="utf-8")
    tree = _module_tree()
    boundary = _named_function(tree, "verify_exported_confirmation_message")
    source = ast.get_source_segment(text, boundary) or ""
    # It never writes, never renames, never re-encodes and never re-frames.
    for forbidden in (
        "open(",
        "write_bytes",
        "write_text",
        "b64encode",
        "MESSAGE_FILE_WRITTEN",
        "INSTALLED_TAG_HELPER_STARTED",
    ):
        assert forbidden not in source, forbidden
    # ``message`` is bound exactly once, by the strict decode.
    rebinds = [
        node
        for node in ast.walk(boundary)
        if isinstance(node, ast.Name)
        and node.id == "message"
        and isinstance(node.ctx, ast.Store)
    ]
    assert len(rebinds) == 1, len(rebinds)
    # It returns the exported bytes, never the reconstructed oracle bytes.
    returns = [node for node in ast.walk(boundary) if isinstance(node, ast.Return)]
    assert len(returns) == 1
    assert isinstance(returns[0].value, ast.Name)
    assert returns[0].value.id == "message"
    writer = ast.get_source_segment(
        text, _named_function(tree, "export_verified_message_and_tag")
    ) or ""
    assert writer.index("verify_exported_confirmation_message") < writer.index(
        "open("
    )
    assert writer.index("open(") < writer.index("runner(")


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


def test_the_submitted_header_value_is_exactly_installed_helper_stdout(workflow):
    """The credential on the wire is parsed from helper stdout and nowhere else."""

    session = workflow.session
    parsed = _tag_from_helper_stdout(session.tagged)
    assert session.tag == parsed
    accepted_route = (
        f"{PREPARATIONS_ROUTE}/{session.exported.preparation_id}/confirmation"
    )
    submitted = [
        record[CONFIRMATION_HEADER]
        for record in session.sent_headers
        if record["path"] == accepted_route and CONFIRMATION_HEADER in record
    ]
    assert submitted, "no confirmation header reached the accepted route"
    # Compared without printing either value, so a failure leaks no credential.
    assert all(
        hmac.compare_digest(value, parsed) for value in submitted
    ), "the submitted header value was not exactly the installed helper's stdout"
    assert len(submitted) == 2, len(submitted)


def test_the_harness_never_falls_back_to_the_in_process_oracle(workflow):
    """A helper that prints a different value is surfaced, never corrected."""

    divergent = "ab" * 32
    assert divergent != workflow.session.tag
    completed = SimpleNamespace(
        returncode=0,
        stderr=b"",
        stdout=divergent.encode("ascii") + os.linesep.encode("ascii"),
    )
    assert _tag_from_helper_stdout(completed) == divergent

    text = MODULE_PATH.read_text(encoding="utf-8")
    tree = _module_tree()
    parser = ast.get_source_segment(
        text, _named_function(tree, "_tag_from_helper_stdout")
    ) or ""
    for forbidden in (
        "compute_historical_pairing_confirmation_tag",
        "hmac",
        "except",
        "SECRET_BYTES",
    ):
        assert forbidden not in parser, forbidden

    # Every value ever placed in the dedicated confirmation header is a
    # helper-derived expression or an explicit negative-control literal; the
    # in-process oracle is never one of them.
    approved = {
        "tag",
        "upper_tag.upper()",
        "flipped",
        "foreign_tag",
        "stale_tag",
        "first.tag",
        '"0" * 64',
        '"a" * 64',
        "parsed",
        "divergent",
    }
    observed = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Name)
                and key.id == "CONFIRMATION_HEADER"
            ):
                observed.add((ast.get_source_segment(text, value) or "").strip())
    assert observed <= approved, observed - approved


def test_no_tag_material_reached_a_file_environment_or_diagnostic(workflow):
    """The credential stays memory-only across every observable channel."""

    tags = {
        workflow.session.tag,
        workflow.restart.tag,
        workflow.session.negatives["foreign_secret_helper_tag"].helper_tag,
    }
    for tag in tags:
        assert tag, "an empty tag would make this scan vacuous"
        encoded = tag.encode("ascii")
        for stream in (
            workflow.session.stdout,
            workflow.session.stderr,
            workflow.restart.stdout,
            workflow.restart.stderr,
        ):
            assert _free_of(stream, encoded)
        for name, value in os.environ.items():
            assert tag not in value, name
        assert tag not in _runbook_text(), "the runbook carries a real tag"
        for record in workflow.session.sent_headers + workflow.restart.sent_headers:
            assert tag not in json.dumps({"path": record["path"]}, sort_keys=True)


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
        ("mutated_helper_stdout", (403, {"error": "CONFIRMATION_REJECTED"})),
        ("foreign_secret_helper_tag", (403, {"error": "CONFIRMATION_REJECTED"})),
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


def test_the_restart_is_a_genuinely_different_terminated_and_restarted_process(
    workflow,
):
    """Pin the restart to two distinct real processes, not a reused object."""

    first = workflow.session
    second = workflow.restart
    assert workflow.restart.startup_refusal is None
    assert first.pid is not None and second.pid is not None
    assert first.pid != second.pid, (first.pid, second.pid)
    assert first.process_object_id != second.process_object_id
    assert first.launcher_object_id != second.launcher_object_id
    # The first child really exited, and it exited before the second one was
    # even constructed, so the second readiness line cannot be the first's.
    assert first.exit_code is not None, "the first launcher never terminated"
    assert second.first_terminated_before_second_start is True
    assert first.closed_at is not None and second.ready_at is not None
    assert first.closed_at < second.ready_at, (first.closed_at, second.ready_at)
    assert second.closed_at is not None and second.closed_at > second.ready_at
    # Both children were started from the same isolated installation.
    scripts = workflow.installation.scripts
    for argv0 in (first.argv0, second.argv0):
        assert Path(argv0).parent == scripts, argv0
        assert Path(argv0).stem == "admissible", argv0
    # Two different runtime roots, so no in-process state could be carried over.
    assert first.runtime != second.runtime
    # The replay is a fresh preparation on the restarted process, not a reset
    # fixture or a reused object.
    assert workflow.restart.replayed is not workflow.session.exported
    assert (
        workflow.restart.replayed.preparation_id
        != workflow.session.exported.preparation_id
    )
    assert (
        workflow.restart.replayed.message_file
        != workflow.session.exported.message_file
    )


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


# ---------------------------------------------------------------------------
# P. Literal execution of every documented executable runbook block.
# ---------------------------------------------------------------------------


# Every fenced block the runbook presents as an executable Windows command,
# identified by its section number and by a stable literal marker.  The meta
# test below requires this inventory and the executed inventory to be equal.
RUNBOOK_EXECUTABLE_BLOCKS = (
    ("extract", "3", "admissible-historical-pairing-v4-extract"),
    ("secret", "4", "RandomNumberGenerator"),
    ("enablement", "5", "UTF8Encoding"),
    ("launch", "6", "--historical-pairing-secret-file"),
    ("message", "10", "FromBase64String"),
    ("integrity", "11", "Get-FileHash"),
    ("tag", "12", "admissible-historical-pairing-tag"),
    ("archive", "15", "Select-Object"),
)

_HEADING_PATTERN = re.compile(r"^## (\d+)\.\s*(.+)$", re.M)
_POWERSHELL_FENCE = re.compile(r"^```powershell\s*\n(.*?)^```\s*$", re.M | re.S)
_PLACEHOLDER_PATTERN = re.compile(r"<[A-Z][A-Z0-9-]*>")


def _sectioned_powershell_blocks(text: str) -> tuple[tuple[str, str], ...]:
    """Return ordered ``(section-number, literal-command)`` pairs."""

    headings = [(match.start(), match.group(1)) for match in _HEADING_PATTERN.finditer(text)]
    blocks = []
    for fence in _POWERSHELL_FENCE.finditer(text):
        section = "0"
        for start, number in headings:
            if start < fence.start():
                section = number
        blocks.append((section, fence.group(1).strip()))
    return tuple(blocks)


def _documented_executable_blocks() -> dict:
    """Bind every documented executable block to its exact committed text."""

    text = _runbook_text()
    blocks = _sectioned_powershell_blocks(text)
    assert len(blocks) == len(RUNBOOK_EXECUTABLE_BLOCKS), (
        "the executable-block inventory drifted from the runbook",
        [section for section, _ in blocks],
    )
    documented = {}
    for (label, section, marker), (observed_section, command) in zip(
        RUNBOOK_EXECUTABLE_BLOCKS, blocks
    ):
        assert observed_section == section, (label, observed_section, section)
        assert marker in command, (label, marker)
        documented[label] = SimpleNamespace(
            label=label, section=section, marker=marker, command=command
        )
    return documented


def _substituted(command: str, replacements: dict) -> str:
    """Replace only documented placeholders, and require every one to be gone."""

    result = command
    for placeholder, value in replacements.items():
        assert placeholder in command, placeholder
        result = result.replace(placeholder, value)
    remaining = _PLACEHOLDER_PATTERN.findall(result)
    assert remaining == [], remaining
    return result


def _powershell_environment(installation) -> dict:
    return {
        "PATH": str(installation.scripts) + os.pathsep + os.environ.get("PATH", "")
    }


def _powershell(command: str, *, env=None, cwd=None, timeout=240):
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        env=env,
        cwd=cwd,
        timeout=timeout,
    )


def _powershell_rows(command: str, *, env=None, timeout=240):
    """Execute a documented command and report the real objects it emitted.

    ``$ErrorActionPreference`` is raised to ``Stop`` and every emitted object is
    printed with its actual property names, so a syntactically accepted but
    semantically useless command -- an invalid ``Select-Object`` property, for
    instance -- cannot pass as a blank column.
    """

    wrapped = (
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; "
        "$rows = @(" + command + "); "
        "foreach ($row in $rows) { [Console]::Out.WriteLine("
        "(($row.PSObject.Properties | ForEach-Object "
        "{ $_.Name + '=' + [string]$_.Value }) -join '|')) }"
    )
    completed = _powershell(wrapped, env=env, timeout=timeout)
    rows = []
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        properties = {}
        for field in line.split("|"):
            name, _, value = field.partition("=")
            properties[name] = value
        rows.append(properties)
    return completed, rows


def _launch_documented_command(command: str, *, env, cwd):
    """Start a documented long-running command and observe its readiness line."""

    argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.update(env)
    SPAWNED_ARGV.append(list(argv))
    SPAWNED_ENVIRONMENT_OVERLAYS.append(dict(env))
    process = subprocess.Popen(
        argv,
        cwd=str(cwd),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
    line = b""
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line or process.poll() is not None:
            break
    readiness = line.decode("utf-8", "replace").strip()
    # The documented launcher is stopped by terminating the whole tree, exactly
    # as Ctrl+C would; nothing is left holding a loopback port.
    _run(["taskkill", "/T", "/F", "/PID", str(process.pid)], timeout=120)
    try:
        remaining_out, remaining_err = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()
        remaining_out, remaining_err = process.communicate(timeout=120)
    return SimpleNamespace(
        readiness=readiness,
        pid=process.pid,
        stdout=line + (remaining_out or b""),
        stderr=remaining_err or b"",
    )


@pytest.fixture(scope="session")
def runbook_execution(workflow, tmp_path_factory):
    """Execute every documented executable runbook block, literally, once."""

    _require_powershell()
    documented = _documented_executable_blocks()
    root = tmp_path_factory.mktemp("runbook")
    assert REPO_ROOT not in root.resolve().parents
    environment = _powershell_environment(workflow.installation)
    coverage: dict = {}

    def _record(label, *, command, completed, **observations):
        coverage[label] = SimpleNamespace(
            label=label,
            section=documented[label].section,
            literal=documented[label].command,
            command=command,
            completed=completed,
            **observations,
        )

    # -- 3. extraction, run against the real acquired wrapper --------------
    work = root / "work"
    work.mkdir()
    (work / "wrapper.json").write_bytes(workflow.wrapper.path.read_bytes())
    extract_command = _substituted(
        documented["extract"].command, {"<WORK-DIR>": str(work)}
    ) + "; exit $LASTEXITCODE"
    extracted = _powershell(extract_command, env=environment)
    _record(
        "extract",
        command=extract_command,
        completed=extracted,
        output=work / "standalone-v4.json",
    )

    # -- 4. exact-byte secret file ----------------------------------------
    secret_path = root / "secret.bin"
    secret_command = _substituted(
        documented["secret"].command, {"<SECRET-FILE>": str(secret_path)}
    )
    secret_executed = _powershell(secret_command, env=environment)
    _record("secret", command=secret_command, completed=secret_executed, path=secret_path)

    # -- 5. enablement document -------------------------------------------
    config_path = root / "historical-pairing.json"
    runbook_archive = root / "archive"
    enablement_command = _substituted(
        documented["enablement"].command,
        {
            "<ENABLEMENT-FILE>": str(config_path),
            "<ARCHIVE-ROOT>": str(runbook_archive),
            "<PAYLOAD-ID>": "runbook-rehearsal-001",
            "<STANDALONE-V4-FILE>": str(work / "standalone-v4.json"),
        },
    )
    enablement_executed = _powershell(enablement_command, env=environment)
    _record(
        "enablement",
        command=enablement_command,
        completed=enablement_executed,
        path=config_path,
        archive_root=runbook_archive,
    )

    # -- 6. the documented launch command, really started ------------------
    runtime = root / "runtime"
    runtime.mkdir()
    launch_command = _substituted(
        documented["launch"].command,
        {
            "<SOURCE-REPOSITORY>": str(workflow.source.path),
            "<REQUIRED-SOURCE-HEAD>": workflow.source.head,
            "<RUNTIME-ROOT>": str(runtime),
            "<BACKEND-EXECUTABLE>": CURSOR_DISCOVERY_COMMAND,
            "<ATTESTATION-CLASS>": "wrapper-chain",
            "<ENABLEMENT-FILE>": str(config_path),
            "<SECRET-FILE>": str(secret_path),
        },
    )
    launched = _launch_documented_command(
        launch_command, env=environment, cwd=runtime
    )
    _record(
        "launch",
        command=launch_command,
        completed=launched,
        runtime=runtime,
        archive_root=runbook_archive,
    )

    # -- 10. public confirmation-message export ----------------------------
    message_path = root / "confirmation-message.bin"
    message_command = _substituted(
        documented["message"].command,
        {
            "<CONFIRMATION-MESSAGE-FILE>": str(message_path),
            "<CONFIRMATION-MESSAGE-BASE64>": base64.b64encode(
                workflow.session.exported.message
            ).decode("ascii"),
        },
    )
    message_executed = _powershell(message_command, env=environment)
    _record(
        "message", command=message_command, completed=message_executed, path=message_path
    )

    # -- 11. integrity verification of the actual selected message file ----
    identity = workflow.session.exported.review["pairing_identity"]
    selected = workflow.session.exported.message_file
    integrity_replacements = {
        "<CONFIRMATION-MESSAGE-BYTE-LENGTH>": str(
            identity["confirmation_message_byte_length"]
        ),
        "<CONFIRMATION-MESSAGE-SHA256>": identity["confirmation_message_sha256"],
        "<CONFIRMATION-MESSAGE-FILE>": str(selected),
    }
    integrity_command = _substituted(
        documented["integrity"].command, integrity_replacements
    )
    integrity_executed = _powershell(
        "$ErrorActionPreference = 'Stop'; " + integrity_command, env=environment
    )
    # Independent negative executions of the very same documented command.
    truncated = root / "truncated.bin"
    truncated.write_bytes(workflow.session.exported.message[:-1])
    rewritten = root / "rewritten.bin"
    rewritten.write_bytes(b"x" + workflow.session.exported.message[1:])
    missing = root / "absent.bin"
    negatives = {}
    for name, replacements in (
        (
            "wrong_length",
            {**integrity_replacements, "<CONFIRMATION-MESSAGE-FILE>": str(truncated)},
        ),
        (
            "wrong_sha256",
            {**integrity_replacements, "<CONFIRMATION-MESSAGE-FILE>": str(rewritten)},
        ),
        (
            "missing_file",
            {**integrity_replacements, "<CONFIRMATION-MESSAGE-FILE>": str(missing)},
        ),
    ):
        negatives[name] = _powershell(
            "$ErrorActionPreference = 'Stop'; "
            + _substituted(documented["integrity"].command, replacements),
            env=environment,
        )
    _record(
        "integrity",
        command=integrity_command,
        completed=integrity_executed,
        selected=selected,
        negatives=negatives,
    )

    # -- 12. the documented tag command ------------------------------------
    tag_command = _substituted(
        documented["tag"].command,
        {
            "<CONFIRMATION-MESSAGE-FILE>": str(message_path),
            "<SECRET-FILE>": str(workflow.secret_file),
        },
    ) + "; exit $LASTEXITCODE"
    tag_executed = _powershell(tag_command, env=environment)
    _record("tag", command=tag_command, completed=tag_executed)

    # -- 15. the documented archive verification ---------------------------
    archive_command = _substituted(
        documented["archive"].command, {"<ARCHIVE-ROOT>": str(workflow.archive_root)}
    )
    archive_executed, archive_rows = _powershell_rows(
        archive_command, env=environment
    )
    # A hidden, recursively nested fourth file must be found by exactly this
    # verification path.  It is created in an isolated copy so the real archive
    # keeps its exactly three canonical documents.
    copied = root / "archive-copy"
    shutil.copytree(workflow.archive_root, copied)
    nested = copied / PROFILE_DIRECTORY_NAME / "nested" / "deeper"
    nested.mkdir(parents=True)
    (nested / "hidden-fourth.json").write_bytes(b"{}")
    nested_command = _substituted(
        documented["archive"].command, {"<ARCHIVE-ROOT>": str(copied)}
    )
    nested_executed, nested_rows = _powershell_rows(nested_command, env=environment)
    # A nonexistent property must fail rather than produce an accepted blank.
    invalid_command = re.sub(
        r"Select-Object\s+.*$",
        "Select-Object NoSuchProperty",
        nested_command,
        flags=re.S,
    )
    invalid_executed, invalid_rows = _powershell_rows(invalid_command, env=environment)
    _record(
        "archive",
        command=archive_command,
        completed=archive_executed,
        rows=archive_rows,
        nested_command=nested_command,
        nested_rows=nested_rows,
        invalid_rows=invalid_rows,
        invalid_completed=invalid_executed,
        copied=copied,
    )
    return SimpleNamespace(root=root, documented=documented, coverage=coverage)


def test_every_documented_executable_block_was_really_executed(runbook_execution):
    """The meta test: documented executable blocks == exercised blocks."""

    documented = set(runbook_execution.documented)
    exercised = set(runbook_execution.coverage)
    assert documented == exercised, documented.symmetric_difference(exercised)
    assert documented == {label for label, _, _ in RUNBOOK_EXECUTABLE_BLOCKS}
    for label, record in runbook_execution.coverage.items():
        assert record.completed is not None, label
        # Every entry is a real execution of the literal committed text with
        # only documented placeholders substituted -- never a substring check.
        # The literal is turned into an exact skeleton in which only the
        # documented placeholders may differ, so no token can be dropped,
        # reordered, or quietly rewritten into a test-only equivalent.
        skeleton = "".join(
            ".+?" if _PLACEHOLDER_PATTERN.fullmatch(part) else re.escape(part)
            for part in re.split(r"(<[A-Z][A-Z0-9-]*>)", record.literal)
        )
        assert re.search(skeleton, record.command, re.S), (label, record.command)
        assert _PLACEHOLDER_PATTERN.findall(record.command) == [], label


def test_documented_extraction_block_writes_the_standalone_document(
    workflow, runbook_execution
):
    record = runbook_execution.coverage["extract"]
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    assert record.completed.stdout.replace(b"\r\n", b"\n").strip() == (
        b"status=STANDALONE_V4_WRITTEN"
    )
    assert record.output.read_bytes() == workflow.standalone_bytes


def test_documented_secret_block_writes_exact_bytes_inside_the_accepted_bounds(
    runbook_execution,
):
    record = runbook_execution.coverage["secret"]
    assert "New-Object byte[]" in record.literal or "byte[]" in record.literal
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    assert record.path.exists()
    assert MIN_CONFIRMATION_SECRET_BYTES <= record.path.stat().st_size <= (
        MAX_CONFIRMATION_SECRET_BYTES
    )


def test_documented_enablement_block_writes_strict_utf8_without_a_bom(
    runbook_execution,
):
    record = runbook_execution.coverage["enablement"]
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    raw = record.path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    document = json.loads(raw.decode("utf-8"))
    assert document["schema_version"] == HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION
    assert Path(document["archive_root"]) == record.archive_root
    assert document["payloads"][0]["payload_id"] == "runbook-rehearsal-001"


def test_documented_launch_block_really_starts_the_installed_launcher(
    runbook_execution,
):
    record = runbook_execution.coverage["launch"]
    match = READINESS_PATTERN.match(record.completed.readiness)
    assert match, (
        record.completed.readiness,
        _bounded_diagnostic(record.completed.stderr),
    )
    assert (record.runtime / "runs").exists() or (
        record.runtime / "contracts"
    ).exists()
    # No confirmation was made through this launch, so it published nothing.
    assert _archive_inventory(record.archive_root) == []
    for candidate in (int(match.group(1)), int(match.group(2))):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(2.0)
            assert probe.connect_ex(("127.0.0.1", candidate)) != 0, candidate
        finally:
            probe.close()


def test_documented_message_block_writes_the_exact_exported_bytes(
    workflow, runbook_execution
):
    record = runbook_execution.coverage["message"]
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    assert record.path.read_bytes() == workflow.session.exported.message


def test_documented_integrity_block_passes_only_on_the_verified_message(
    runbook_execution,
):
    """Step 11 runs literally, against the actual operator-selected file."""

    record = runbook_execution.coverage["integrity"]
    assert str(record.selected) in record.command
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    assert b"confirmation message integrity verified" in record.completed.stdout
    for name, expected in (
        ("wrong_length", b"declared length mismatch"),
        ("wrong_sha256", b"declared sha256 mismatch"),
    ):
        negative = record.negatives[name]
        assert negative.returncode != 0, name
        assert expected in negative.stderr, (name, _bounded_diagnostic(negative.stderr))
        assert b"confirmation message integrity verified" not in negative.stdout, name
    missing = record.negatives["missing_file"]
    assert missing.returncode != 0
    assert b"confirmation message integrity verified" not in missing.stdout


def test_documented_tag_block_reproduces_exactly_the_submitted_credential(
    workflow, runbook_execution
):
    record = runbook_execution.coverage["tag"]
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    printed = record.completed.stdout.decode("ascii").strip()
    assert printed == workflow.session.tag
    assert len(printed) == 64


def test_documented_archive_block_reports_exactly_three_verifiable_rows(
    workflow, runbook_execution
):
    record = runbook_execution.coverage["archive"]
    assert "Get-ChildItem" in _runbook_text()
    # The documented command must request exactly the two verifiable columns.
    assert "Select-Object FullName, Length" in record.literal, record.literal
    assert record.completed.returncode == 0, _bounded_diagnostic(
        record.completed.stderr
    )
    assert len(record.rows) == 3, record.rows
    suffixes = set()
    for row in record.rows:
        assert set(row) == {"FullName", "Length"}, row
        assert row["FullName"].strip(), row
        assert Path(row["FullName"]).is_file(), row
        assert int(row["Length"]) > 0, row
        suffixes.add(Path(row["FullName"]).name.split(".", 1)[1])
    assert suffixes == {
        PROFILE_FILE_SUFFIX.lstrip("."),
        PAYLOAD_FILE_SUFFIX.lstrip("."),
        AUTHORITY_FILE_SUFFIX.lstrip("."),
    }, suffixes
    # The complete verification path detects a hidden, recursively nested file.
    assert len(record.nested_rows) == 4, record.nested_rows
    assert any(
        row["FullName"].endswith("hidden-fourth.json") for row in record.nested_rows
    )
    # An invalid property is a failure, not an accepted blank column.
    invalid_names = {name for row in record.invalid_rows for name in row}
    assert invalid_names != {"FullName", "Length"}, record.invalid_rows
    assert invalid_names <= {"NoSuchProperty"}, invalid_names
    # The real archive was never touched by any of this.
    assert len(_archive_inventory(workflow.archive_root)) == 3


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


# ---------------------------------------------------------------------------
# R. The browser-evidence claim guard.
# ---------------------------------------------------------------------------


# Wording that would upgrade the committed served-asset smoke into a claim the
# evidence does not support.  A match is refused unless the very same sentence
# negates it immediately, with no clause boundary in between.
BROWSER_CLAIM_PATTERNS = (
    r"browser[\s\-]*proven",
    r"proven[\s\-]*(?:by|via|with|in)[\s\w,]{0,20}browser",
    r"real[\s\-]*browser[\s\w,]{0,40}end[\s\-]*to[\s\-]*end",
    r"end[\s\-]*to[\s\-]*end[\s\w,]{0,40}browser",
    r"browser[\s\w,]{0,40}download[\s\w,]{0,20}verified",
    r"verified[\s\w,]{0,30}browser[\s\w,]{0,20}download",
    r"automated[\s\w,]{0,20}browser[\s\w,]{0,30}download",
    r"browser[\s\w,]{0,30}successfully[\s\w,]{0,20}download",
    r"download[\s\w,]{0,20}verified[\s\w,]{0,20}end[\s\-]*to[\s\-]*end",
)
# Wording that accurately scopes what the committed evidence really shows.
ACCURATE_BROWSER_SCOPES = (
    "served-asset smoke",
    "asset wiring verified",
    "not a real-browser end-to-end proof",
    "the operator performs the browser download interactively",
)
_NEGATED_IMMEDIATELY = re.compile(
    r"\b(?:not|never|no|without|rather than|neither)\b[^:;.]{0,40}$",
    re.I,
)


def _unqualified_browser_claims(text: str) -> list[str]:
    """Return every browser-proof claim that is not immediately negated."""

    lowered = " ".join(text.lower().split())
    offences = []
    for pattern in BROWSER_CLAIM_PATTERNS:
        for match in re.finditer(pattern, lowered):
            window = lowered[max(0, match.start() - 42) : match.start()]
            if _NEGATED_IMMEDIATELY.search(window):
                continue
            offences.append(
                lowered[max(0, match.start() - 60) : match.end() + 40]
            )
    return offences


def _module_docstrings() -> list[str]:
    tree = _module_tree()
    found = [ast.get_docstring(tree) or ""]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            found.append(ast.get_docstring(node) or "")
    return [item for item in found if item]


def test_the_browser_claim_guard_itself_rejects_an_upgraded_claim():
    """The guard must be semantic enough to kill a claim-upgrading mutation."""

    for forged in (
        "The asset smoke is a browser-proven download.",
        "This is a real-browser end-to-end download of the message.",
        "Browser download verified end to end.",
        "An automated browser successfully downloaded the message.",
        "The message download was verified end to end by a real browser.",
    ):
        assert _unqualified_browser_claims(forged), forged
    for accurate in ACCURATE_BROWSER_SCOPES + (
        "This is a served-asset smoke and not a real-browser end-to-end proof.",
        "No browser-proven download is claimed anywhere.",
        "The operator performs the browser download interactively.",
    ):
        assert _unqualified_browser_claims(accurate) == [], accurate
    # A clause boundary must not let a negation elsewhere launder the claim.
    assert _unqualified_browser_claims(
        "This is not a smoke: it is a browser-proven download."
    )


def test_the_runbook_never_claims_a_browser_proven_download():
    text = _runbook_text()
    assert _unqualified_browser_claims(text) == [], _unqualified_browser_claims(text)
    lowered = " ".join(text.lower().split())
    for required in (
        "not a real-browser end-to-end proof",
        "the operator performs the browser download interactively",
    ):
        assert required in lowered, required


def test_no_test_docstring_claims_a_browser_proven_download():
    for docstring in _module_docstrings():
        assert _unqualified_browser_claims(docstring) == [], docstring[:200]
    smoke = _named_function(
        _module_tree(),
        "test_visible_download_action_exposes_the_same_launcher_supplied_bytes",
    )
    docstring = " ".join((ast.get_docstring(smoke) or "").lower().split())
    assert "no browser is driven here" in docstring
    assert "not presented as an end-to-end browser proof" in docstring
    module_docstring = " ".join(
        (ast.get_docstring(_module_tree()) or "").lower().split()
    )
    assert "served-asset smoke" in module_docstring
    assert "not a real-browser end-to-end proof" in module_docstring


# ---------------------------------------------------------------------------
# S. No silent early return may turn an untested path into a pass.
# ---------------------------------------------------------------------------


def test_no_test_function_contains_an_early_return():
    tree = _module_tree()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        returns = [
            child for child in ast.walk(node) if isinstance(child, ast.Return)
        ]
        assert returns == [], (node.name, [item.lineno for item in returns])


def test_every_test_function_ends_through_at_least_one_assertion():
    tree = _module_tree()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        assertions = [
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Assert)
            or (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "raises"
            )
        ]
        assert assertions, node.name


def test_every_recorded_startup_refusal_path_is_asserted_by_a_test(workflow):
    """A refused startup is recorded, then asserted -- never silently passed."""

    assert workflow.session.startup_refusal is None
    assert workflow.restart.startup_refusal is None
    text = MODULE_PATH.read_text(encoding="utf-8")
    assert "assert session.startup_refusal is None" in text
    assert "assert workflow.restart.startup_refusal is None" in text
    # The archive verification test executes a real command unconditionally, so
    # no PowerShell-absent branch can turn an untested path into a pass.
    archive_test = _named_function(
        _module_tree(),
        "test_documented_archive_block_reports_exactly_three_verifiable_rows",
    )
    branches = [
        node
        for node in ast.walk(archive_test)
        if isinstance(node, (ast.If, ast.IfExp))
    ]
    assert branches == [], [node.lineno for node in branches]
    assert [argument.arg for argument in archive_test.args.args] == [
        "workflow",
        "runbook_execution",
    ]


# ---------------------------------------------------------------------------
# T. The final supported-host selection contains no skip at all.
# ---------------------------------------------------------------------------


def test_exactly_one_positive_supported_host_real_path_witness_exists():
    text = MODULE_PATH.read_text(encoding="utf-8")
    witness = _named_function(
        _module_tree(),
        "test_supported_host_executed_the_real_wrapper_acquisition_path",
    )
    source = ast.get_source_segment(text, witness) or ""
    for required in (
        "real_wrapper_acquisition",
        "real_path_executed",
        "substituted is False",
        "PREFLIGHT_READY",
        "attestation_class == ATTESTATION_CLASS_WRAPPER_CHAIN",
        "provider_invocations == 0",
        "run_root_created is False",
        "_installed_operator_workflow",
    ):
        assert required in source, required
    # The witness depends on the acquisition fixture alone, so a downstream
    # workflow skip can never take it with it.
    assert [argument.arg for argument in witness.args.args] == [
        "real_wrapper_acquisition"
    ]


def test_the_final_supported_host_selection_contains_no_skip(_skip_ledger):
    """The last word: on a supported host this module skips nothing at all."""

    _require_supported_operator_host()
    allowed = () if powershell_is_available() else (POWERSHELL_SKIP_REASON,)
    unexpected = [
        entry
        for entry in _skip_ledger
        if not any(reason in entry[2] for reason in allowed)
    ]
    assert unexpected == [], unexpected
    if not allowed:
        assert _skip_ledger == [], _skip_ledger
