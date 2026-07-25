"""CLI entry: ``python -m admissible.product_launcher``.

Historical pairing operator startup
-----------------------------------

This module is the operator startup surface for the optional historical
evaluation pairing feature, and it is deliberately nothing more than that.  It
selects and supplies; it never decides.  Two filesystem locators arrive on the
command line, the two accepted loaders turn them into exactly one accepted
non-secret configuration object and exactly one exact-byte secret, and both
values are handed to the accepted ``ProductLauncher`` keyword-only seam
unchanged.

What this entrypoint owns
-------------------------

* the two option strings and their conversion to ``Path`` and nothing else;
* the four-state presence matrix over those two options;
* the order in which the two accepted loaders run, both strictly before
  ``ProductLauncher`` construction;
* one bounded, fixed-code startup refusal with one fixed exit code;
* dropping its own local reference to the configured secret.

What this entrypoint deliberately does not own
----------------------------------------------

Path validation, document parsing, schema law, payload loading, registry
construction, coordinator construction, feature composition, and every
confidentiality property of the loaded values belong to the accepted lower
layers and are never reimplemented, re-validated, or second-guessed here.  This
module constructs no V4, no V5, no pairing authority, and no combined
secret-bearing object; it computes no tag, performs no HMAC, reads no archive
and no confirmation message, and evaluates no result.  The non-secret
configuration and the secret bytes stay two separate arguments: neither is ever
placed in ``LauncherConfiguration``.

Explicit locators only
----------------------

Both new options are filesystem locators.  Neither accepts literal secret
bytes, a Base64 or hex secret, secret text, an environment-variable name, an
expected or presented tag, a V5 document, a pairing authority, or an archive
receipt.  There is no environment fallback, no standard-input fallback, no
interactive prompt, no keyring, no automatic file creation, and no implicit
default.  The parser converts each argument directly into a ``Path`` and stops
there: it never resolves, absolutizes, expands ``~``, expands an environment
variable, or normalizes a relative path into an accepted one.  The accepted
loaders remain the sole validators of both source-file paths, so a relative or
non-canonical locator is refused by them and never quietly repaired here.

Ordering and side effects
-------------------------

For an enabled launch the real order is: parse arguments, build and validate the
ordinary ``LauncherConfiguration`` exactly as before, validate the presence
matrix, load the non-secret enablement document, read the exact secret bytes,
construct ``ProductLauncher`` with both values, start, print the existing
readiness line, serve, and close in the existing ``finally`` path.  Because both
loaders complete before construction, every loader failure happens before the
source-HEAD subprocess verification, before preflight and product-control worker
creation, before run and contract directory creation, and before the G2 and UI
sockets are bound.  Nothing historical is loaded lazily or after start.

When neither option is present the feature stays off: neither loader runs, no
historical file is read, ``ProductLauncher(configuration)`` is called exactly as
before with no explicit historical ``None`` keyword arguments, and browser
discovery of the historical route receives exactly the ordinary existing 404.
Exactly one option present is a startup defect, never a quiet disable.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from types import MappingProxyType
from typing import Mapping

from admissible.delegated_gate.historical_pairing_workflow import (
    InvalidPairingCoordinatorConfiguration,
)
from admissible.historical_pairing_secret_file import (
    HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES,
    HistoricalPairingSecretFileError,
    read_historical_pairing_secret_file,
)
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
    LauncherConfiguration,
)
from admissible.product_launcher.historical_pairing_enablement import (
    HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES,
    HistoricalPairingEnablementDocumentError,
    load_historical_pairing_configuration,
)
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPayloadNotFound,
    HistoricalPayloadRegistryError,
    InvalidHistoricalPairingConfiguration,
    MalformedHistoricalPayloadDocument,
)
from admissible.product_launcher.historical_pairing_service import (
    HistoricalPairingFeatureConfigurationError,
)
from admissible.product_launcher.launcher import ProductLauncher


# One fixed exit code for every recognized historical startup refusal.  Success
# still exits 0, ``--help`` still exits 0, and an argparse usage failure still
# exits 2.
HISTORICAL_PAIRING_STARTUP_EXIT_CODE = 3

# Fixed, bounded, path-free entrypoint-owned failure codes.  A code carries no
# configured secret, secret fragment, secret encoding, observed secret length,
# configuration content, payload content, archive content, exception text,
# exception repr, exception argument, cause, context, note, or memory address.
HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE = (
    "HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE"
)
HISTORICAL_PAIRING_CONFIGURATION_INVALID = "HISTORICAL_PAIRING_CONFIGURATION_INVALID"
HISTORICAL_PAIRING_PAYLOAD_REFUSED = "HISTORICAL_PAIRING_PAYLOAD_REFUSED"
HISTORICAL_PAIRING_STARTUP_REFUSED = "HISTORICAL_PAIRING_STARTUP_REFUSED"

# Every code this entrypoint may ever emit: its own four plus the two accepted
# loaders' own frozen, already-bounded code sets.
HISTORICAL_PAIRING_STARTUP_ERROR_CODES = frozenset(
    {
        HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE,
        HISTORICAL_PAIRING_CONFIGURATION_INVALID,
        HISTORICAL_PAIRING_PAYLOAD_REFUSED,
        HISTORICAL_PAIRING_STARTUP_REFUSED,
    }
    | HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES
    | HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES
)

# The two accepted public error types whose own bounded ``.code`` may be emitted
# directly, each with the frozen code set that type is allowed to carry.  A code
# outside its type's set is never emitted.
_HISTORICAL_BOUNDED_CODE_TYPES: Mapping[type, frozenset[str]] = MappingProxyType(
    {
        HistoricalPairingEnablementDocumentError: (
            HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES
        ),
        HistoricalPairingSecretFileError: HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES,
    }
)

# Exact-type mapping for the accepted downstream failures that can escape
# ``ProductLauncher`` construction through the historical seam:
#
#   * ``InvalidHistoricalPairingConfiguration`` -- the accepted configuration
#     type's own validation, raised by the enablement loader's final
#     ``validated()`` call and again by the registry, plus the registry's
#     duplicate-payload-fingerprint law;
#   * ``MalformedHistoricalPayloadDocument`` -- one configured standalone V4
#     payload document refused by the registry;
#   * ``HistoricalPairingFeatureConfigurationError`` -- the accepted
#     feature-construction refusals, including an empty configured payload list;
#   * ``HistoricalPayloadRegistryError`` and ``HistoricalPayloadNotFound`` --
#     explicitly recognized historical errors with no narrower classification;
#   * ``InvalidPairingCoordinatorConfiguration`` -- the accepted coordinator's
#     own configuration refusal, likewise recognized but not narrowly classified.
#
# The mapping is keyed by exact type.  There is no inheritance mapping, no class
# name matching, no message matching, and no exception chaining, so an
# unregistered subclass of any entry below can never inherit that entry's narrow
# code: it is simply unrecognized and keeps ordinary exception behavior.
_HISTORICAL_STARTUP_CODES: Mapping[type, str] = MappingProxyType(
    {
        InvalidHistoricalPairingConfiguration: (
            HISTORICAL_PAIRING_CONFIGURATION_INVALID
        ),
        MalformedHistoricalPayloadDocument: HISTORICAL_PAIRING_PAYLOAD_REFUSED,
        HistoricalPairingFeatureConfigurationError: (
            HISTORICAL_PAIRING_CONFIGURATION_INVALID
        ),
        HistoricalPayloadRegistryError: HISTORICAL_PAIRING_STARTUP_REFUSED,
        HistoricalPayloadNotFound: HISTORICAL_PAIRING_STARTUP_REFUSED,
        InvalidPairingCoordinatorConfiguration: HISTORICAL_PAIRING_STARTUP_REFUSED,
    }
)


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
    # Both historical options are filesystem locators. ``type=Path`` performs
    # exactly one conversion and no interpretation: no resolve, no absolutize, no
    # ``~`` expansion, no environment expansion, and no normalization of a
    # relative value into an accepted one. The accepted loaders decide every path
    # question. Absent means absent: the default is None, never a discovered or
    # implied file.
    parser.add_argument(
        "--historical-pairing-config",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "absolute path to the non-secret historical pairing enablement "
            "document; requires --historical-pairing-secret-file"
        ),
    )
    parser.add_argument(
        "--historical-pairing-secret-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "absolute path to the file whose exact bytes are the configured "
            "historical pairing confirmation secret; requires "
            "--historical-pairing-config"
        ),
    )
    return parser


def _historical_startup_code(exc: BaseException) -> str | None:
    """Resolve one fixed code from the exception's exact type, or ``None``.

    Only ``type(exc)`` is ever consulted.  The exception's ``str``, ``repr``,
    ``args``, attributes, ``__cause__``, ``__context__``, and ``__notes__`` are
    never read, so nothing hostile an exception carries can reach the operator.
    ``None`` means "not a recognized historical startup refusal", and the caller
    must then preserve exactly the pre-existing behavior for that exception.
    """

    exact = type(exc)
    allowed = _HISTORICAL_BOUNDED_CODE_TYPES.get(exact)
    if allowed is not None:
        # These two accepted types own a fixed bounded code. It is emitted only
        # when it really belongs to that exact type's frozen allowed set;
        # anything else collapses to the generic refusal.
        code = getattr(exc, "code", None)
        if type(code) is str and code in allowed:
            return code
        return HISTORICAL_PAIRING_STARTUP_REFUSED
    return _HISTORICAL_STARTUP_CODES.get(exact)


def _refuse_historical_startup(code: str) -> int:
    """Emit exactly one bounded line to stderr and nothing at all to stdout."""

    bounded = (
        code
        if code in HISTORICAL_PAIRING_STARTUP_ERROR_CODES
        else HISTORICAL_PAIRING_STARTUP_REFUSED
    )
    sys.stderr.write(f"error={bounded}\n")
    sys.stderr.flush()
    return HISTORICAL_PAIRING_STARTUP_EXIT_CODE


def _launcher_with_historical_pairing(
    configuration: LauncherConfiguration,
    *,
    configuration_path: Path,
    secret_path: Path,
) -> ProductLauncher:
    """Load both accepted values in order, then construct the launcher with them.

    The non-secret enablement document is loaded first and the exact secret bytes
    second, so a defective configuration is refused before any secret file is
    opened.  Both loaders complete before ``ProductLauncher`` is called, and the
    exact objects they returned are passed through unchanged: nothing here
    copies, rebuilds, serializes, wraps, normalizes, decodes, or re-encodes
    either value.
    """

    loaded_configuration = load_historical_pairing_configuration(
        path=configuration_path
    )
    secret = read_historical_pairing_secret_file(path=secret_path)
    try:
        return ProductLauncher(
            configuration,
            historical_pairing_configuration=loaded_configuration,
            historical_pairing_secret=secret,
        )
    finally:
        # Reference minimization only, and deliberately honest about its limit:
        # rebinding the local reference does not zeroize immutable Python bytes.
        # The coordinator retains the configured secret for the launcher
        # lifetime. Dropping the local reference here also keeps the secret out
        # of this frame's locals when the frame is retained by a traceback.
        secret = None


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
    configuration_path = args.historical_pairing_config
    secret_path = args.historical_pairing_secret_file
    if (configuration_path is None) != (secret_path is None):
        # Exactly one locator is a startup defect, refused before either loader
        # runs, before any historical file is opened, and before any launcher,
        # worker, directory, or socket exists.
        return _refuse_historical_startup(HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE)
    if configuration_path is None:
        launcher = ProductLauncher(configuration)
    else:
        try:
            launcher = _launcher_with_historical_pairing(
                configuration,
                configuration_path=configuration_path,
                secret_path=secret_path,
            )
        except Exception as exc:
            code = _historical_startup_code(exc)
            if code is None:
                # Not a recognized historical failure. An invalid source
                # repository, a source HEAD mismatch, and every existing G2 or UI
                # construction failure therefore keep exactly the behavior they
                # had before this feature existed, even though the historical
                # options were supplied on the same command line.
                raise
            return _refuse_historical_startup(code)
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
