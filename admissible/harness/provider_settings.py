"""Local-only provider settings helper for Admissible live model configuration.

Writes a JSON settings file under .admissible/ and optionally prints
PowerShell environment-variable commands. This is not a product UI and
does not transmit secrets over the network.

Secrets are stored locally only and must not be committed to Git.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Any

from admissible.runner.model_clients import (
    DEFAULT_HF_BASE_URL,
    DEFAULT_HF_TIMEOUT_SECONDS,
    HF_BASE_URL_ENV,
    HF_MODEL_ENV,
    HF_TOKEN_ENV,
)

DEFAULT_PROVIDER = "hf"
DEFAULT_API_KEY_ENV_VAR = HF_TOKEN_ENV
DEFAULT_SETTINGS_FILENAME = "local_provider_settings.json"
HTML_TEMPLATE_PATH = Path(__file__).resolve().parent / "provider_settings.html"

TOKEN_FIELD_WARNING = (
    "A raw token field was supplied. Tokens are local-only, ignored by Git, "
    "and should not be committed. Prefer setting api_key_env_var and exporting "
    "the token in your shell instead."
)


def default_settings() -> dict[str, Any]:
    """Return the default provider settings document."""
    return {
        "provider": DEFAULT_PROVIDER,
        "base_url": DEFAULT_HF_BASE_URL,
        "model": "",
        "api_key_env_var": DEFAULT_API_KEY_ENV_VAR,
        "timeout_seconds": int(DEFAULT_HF_TIMEOUT_SECONDS),
    }


def build_settings(
    *,
    provider: str = DEFAULT_PROVIDER,
    base_url: str = DEFAULT_HF_BASE_URL,
    model: str = "",
    api_key_env_var: str = DEFAULT_API_KEY_ENV_VAR,
    timeout_seconds: int | float = DEFAULT_HF_TIMEOUT_SECONDS,
    token: str | None = None,
) -> dict[str, Any]:
    """Build a settings dict, preferring api_key_env_var over a raw token."""
    settings = {
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "api_key_env_var": api_key_env_var,
        "timeout_seconds": int(timeout_seconds),
    }
    if token is not None and token.strip():
        warnings.warn(TOKEN_FIELD_WARNING, stacklevel=2)
        settings["token"] = token.strip()
    return settings


def write_settings(path: str | Path, settings: dict[str, Any]) -> Path:
    """Write settings JSON to path, creating parent directories as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def format_powershell_commands(
    settings: dict[str, Any],
    *,
    token: str | None = None,
) -> str:
    """Format PowerShell env-var commands. Omits token unless explicitly supplied."""
    from admissible.runner.model_clients import HF_TIMEOUT_ENV

    api_key_env_var = settings.get("api_key_env_var") or DEFAULT_API_KEY_ENV_VAR
    lines: list[str] = []

    if token is not None and token.strip():
        lines.append(f'$env:{api_key_env_var}="{token.strip()}"')
    else:
        lines.append(f'# Set token locally (not printed): $env:{api_key_env_var}="<your-token>"')

    lines.extend([
        f'$env:{HF_MODEL_ENV}="{settings.get("model", "")}"',
        f'$env:{HF_BASE_URL_ENV}="{settings.get("base_url", DEFAULT_HF_BASE_URL)}"',
        f'$env:{HF_TIMEOUT_ENV}="{settings.get("timeout_seconds", int(DEFAULT_HF_TIMEOUT_SECONDS))}"',
    ])

    return "\n".join(lines) + "\n"


def load_html_template() -> str:
    """Return the static HTML documentation template."""
    return HTML_TEMPLATE_PATH.read_text(encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.harness.provider_settings",
        description=(
            "Write local Admissible provider settings JSON for Hugging Face "
            "Inference Providers. Secrets stay local; do not commit output."
        ),
    )
    parser.add_argument(
        "--out",
        default=f".admissible/{DEFAULT_SETTINGS_FILENAME}",
        help="Path to write settings JSON (default: .admissible/local_provider_settings.json).",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Model name to record in settings.",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_HF_BASE_URL,
        help=f"Hugging Face base URL (default: {DEFAULT_HF_BASE_URL}).",
    )
    parser.add_argument(
        "--api-key-env-var",
        default=DEFAULT_API_KEY_ENV_VAR,
        help=f"Environment variable name for the API token (default: {DEFAULT_API_KEY_ENV_VAR}).",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=int(DEFAULT_HF_TIMEOUT_SECONDS),
        help=f"Request timeout in seconds (default: {int(DEFAULT_HF_TIMEOUT_SECONDS)}).",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Optional raw token to store locally (discouraged; never printed in normal output).",
    )
    parser.add_argument(
        "--print-powershell",
        action="store_true",
        help="Print PowerShell commands to set environment variables.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    settings = build_settings(
        model=args.model,
        base_url=args.base_url,
        api_key_env_var=args.api_key_env_var,
        timeout_seconds=args.timeout_seconds,
        token=args.token,
    )
    out_path = write_settings(args.out, settings)

    summary = {
        "written": str(out_path),
        "provider": settings["provider"],
        "api_key_env_var": settings["api_key_env_var"],
        "has_token_field": "token" in settings,
        "warning": TOKEN_FIELD_WARNING if "token" in settings else None,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.print_powershell:
        print(format_powershell_commands(settings, token=args.token), end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())
