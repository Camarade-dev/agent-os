"""CLI entry: ``python -m admissible.product_launcher``."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.launcher import ProductLauncher


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.product_launcher",
        description="Browser-safe Admissible product launcher (G2.5)",
    )
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--required-source-head", required=True)
    parser.add_argument("--run-parent", required=True)
    parser.add_argument("--contract-documents-directory", required=True)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--executable-prefix-arg", action="append", default=[])
    parser.add_argument("--attestation-class", default="package-bin")
    parser.add_argument("--model-default", default="auto")
    parser.add_argument("--timeout-default", type=int, default=600)
    parser.add_argument("--timeout-maximum", type=int, default=3600)
    parser.add_argument("--stdout-byte-limit", type=int, default=8_388_608)
    parser.add_argument("--stderr-byte-limit", type=int, default=1_048_576)
    parser.add_argument("--ui-port", type=int, default=0)
    parser.add_argument("--g2-port", type=int, default=0)
    parser.add_argument(
        "--authorization-mode",
        choices=[AUTHORIZATION_MODE_PRECOMMITTED, AUTHORIZATION_MODE_INTERACTIVE],
        default=AUTHORIZATION_MODE_PRECOMMITTED,
    )
    parser.add_argument("--no-browser", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configuration = LauncherConfiguration(
        source_repository=Path(args.source_repository).resolve(),
        required_source_head=args.required_source_head.lower(),
        run_parent=Path(args.run_parent).resolve(),
        contract_documents_directory=Path(args.contract_documents_directory).resolve(),
        executable=args.executable,
        executable_prefix_args=tuple(args.executable_prefix_arg),
        attestation_class=args.attestation_class,
        model_default=args.model_default,
        timeout_default=args.timeout_default,
        timeout_maximum=args.timeout_maximum,
        stdout_byte_limit=args.stdout_byte_limit,
        stderr_byte_limit=args.stderr_byte_limit,
        product_ui_bind_host="127.0.0.1",
        product_ui_bind_port=args.ui_port,
        g2_bind_host="127.0.0.1",
        g2_bind_port=args.g2_port,
        authorization_mode=args.authorization_mode,
        open_browser=not args.no_browser,
    ).validated()
    launcher = ProductLauncher(configuration)
    try:
        launcher.start()
        print(
            f"ui=http://127.0.0.1:{launcher.ui_port}/ g2_port={launcher.g2_port}",
            flush=True,
        )
        launcher.serve_forever()
    finally:
        launcher.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
