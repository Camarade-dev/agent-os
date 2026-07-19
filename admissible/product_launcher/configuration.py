"""Immutable launcher/runtime configuration for G2.5 product authoring."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess

AUTHORIZATION_MODE_PRECOMMITTED = "PRECOMMITTED_DIGEST"
AUTHORIZATION_MODE_INTERACTIVE = "INTERACTIVE_BOUND_CONFIRMATION"
AUTHORIZATION_MODES = frozenset(
    {AUTHORIZATION_MODE_PRECOMMITTED, AUTHORIZATION_MODE_INTERACTIVE}
)
DEFAULT_TEMPLATE_ID = "observed-local-git-v1"
SUPPORTED_TEMPLATE_IDS = (DEFAULT_TEMPLATE_ID,)
LOOPBACK_HOST = "127.0.0.1"


@dataclass(frozen=True)
class LauncherConfiguration:
    """Non-secret values shared by authoring, preflight, and G2 construction.

    Secrets (G2 token, UI CSRF nonce, owner phrase/digest) are never stored here.
    The source repository and required HEAD are fixed for one launcher process.
    """

    source_repository: Path
    required_source_head: str
    run_parent: Path
    contract_documents_directory: Path
    executable: str
    executable_prefix_args: tuple[str, ...]
    attestation_class: str
    model_default: str
    timeout_default: int
    timeout_maximum: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    product_ui_bind_host: str
    product_ui_bind_port: int
    g2_bind_host: str
    g2_bind_port: int
    authorization_mode: str
    open_browser: bool
    template_ids: tuple[str, ...] = SUPPORTED_TEMPLATE_IDS
    preflight_timeout_seconds: int = 120
    preflight_stdout_byte_limit: int = 2 * 1024 * 1024
    preflight_stderr_byte_limit: int = 256 * 1024
    max_authored_contracts: int = 64
    max_preparations: int = 32
    preparation_ttl_seconds: int = 3600

    def validated(self) -> "LauncherConfiguration":
        source = Path(self.source_repository)
        if not source.is_absolute():
            raise ValueError("source repository must be absolute")
        canonical = Path(os.path.abspath(os.fspath(source)))
        if str(canonical) != str(source):
            raise ValueError("source repository must be canonical")
        if not canonical.is_dir():
            raise ValueError("source repository must be an existing directory")
        run_parent = Path(self.run_parent)
        documents = Path(self.contract_documents_directory)
        if not run_parent.is_absolute() or not documents.is_absolute():
            raise ValueError("run parent and contract document directory must be absolute")
        if run_parent.resolve() == documents.resolve():
            raise ValueError("contract document directory must be separate from run parent")
        if self.product_ui_bind_host != LOOPBACK_HOST or self.g2_bind_host != LOOPBACK_HOST:
            raise ValueError("only exact 127.0.0.1 binding is permitted")
        for port in (self.product_ui_bind_port, self.g2_bind_port):
            if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
                raise ValueError("invalid bind port")
        if self.authorization_mode not in AUTHORIZATION_MODES:
            raise ValueError("unsupported authorization mode")
        if not isinstance(self.open_browser, bool):
            raise ValueError("open_browser must be boolean")
        if not isinstance(self.executable, str) or not self.executable:
            raise ValueError("executable is required")
        if self.attestation_class not in {"package-bin", "wrapper-chain"}:
            raise ValueError("unsupported attestation class")
        if not isinstance(self.executable_prefix_args, tuple):
            raise ValueError("executable prefix args must be a tuple")
        if not isinstance(self.required_source_head, str) or not self.required_source_head:
            raise ValueError("required source HEAD is required")
        if self.required_source_head != self.required_source_head.lower() or any(
            char not in "0123456789abcdef" for char in self.required_source_head
        ):
            raise ValueError("required source HEAD must be a lowercase hex Git object ID")
        if len(self.required_source_head) not in {40, 64}:
            raise ValueError("required source HEAD must be a lowercase hex Git object ID")
        for name, value, minimum, maximum in (
            ("timeout_default", self.timeout_default, 1, 3600),
            ("timeout_maximum", self.timeout_maximum, 1, 3600),
            ("stdout_byte_limit", self.stdout_byte_limit, 1, 16 * 1024 * 1024),
            ("stderr_byte_limit", self.stderr_byte_limit, 1, 16 * 1024 * 1024),
            ("preflight_timeout_seconds", self.preflight_timeout_seconds, 1, 3600),
            ("preflight_stdout_byte_limit", self.preflight_stdout_byte_limit, 1024, 8 * 1024 * 1024),
            ("preflight_stderr_byte_limit", self.preflight_stderr_byte_limit, 1024, 8 * 1024 * 1024),
            ("max_authored_contracts", self.max_authored_contracts, 1, 10_000),
            ("max_preparations", self.max_preparations, 1, 10_000),
            ("preparation_ttl_seconds", self.preparation_ttl_seconds, 1, 86_400),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{name} out of bounds")
        if self.timeout_default > self.timeout_maximum:
            raise ValueError("timeout default cannot exceed timeout maximum")
        if not self.template_ids or any(not isinstance(item, str) or not item for item in self.template_ids):
            raise ValueError("template_ids must be a non-empty string tuple")
        for item in self.template_ids:
            if item not in SUPPORTED_TEMPLATE_IDS:
                raise ValueError(f"unsupported template id: {item}")
        return self


def verify_required_source_head(configuration: LauncherConfiguration) -> str:
    """Observe the source repository HEAD and require an exact match."""

    completed = subprocess.run(
        ["git", "-C", str(configuration.source_repository), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise ValueError("unable to observe source repository HEAD")
    observed = completed.stdout.strip().lower()
    if observed != configuration.required_source_head:
        raise ValueError("source repository HEAD does not match required HEAD")
    return observed


__all__ = [
    "AUTHORIZATION_MODE_INTERACTIVE",
    "AUTHORIZATION_MODE_PRECOMMITTED",
    "AUTHORIZATION_MODES",
    "DEFAULT_TEMPLATE_ID",
    "LOOPBACK_HOST",
    "LauncherConfiguration",
    "SUPPORTED_TEMPLATE_IDS",
    "verify_required_source_head",
]
