"""Pinned Codex 0.145.0 schema identity and small Draft-07 validator.

The runtime dependency set stays standard-library-only.  This validator
implements the schema keywords used by the checked-in generated lifecycle
schemas; unsupported validation keywords fail closed when encountered.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib.resources import files
from typing import Any, Mapping

from admissible.capsule.common import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_sha256,
    sha256_bytes,
    strict_json_loads,
)


CODEX_APP_SERVER_PROTOCOL_VERSION = "0.145.0"
SCHEMA_MANIFEST_VERSION = "admissible_codex_app_server_schema_manifest_v1"


def _schema_root():
    return files("admissible.capsule.protocol_schemas")


def schema_manifest() -> Mapping[str, Any]:
    raw = _schema_root().joinpath("manifest.json").read_bytes()
    decoded = strict_json_loads(raw, label="Codex schema manifest")
    require_exact_keys(
        decoded,
        {
            "schema_version",
            "codex_cli_version",
            "complete_v2_bundle_sha256",
            "files",
        },
        "Codex schema manifest",
    )
    if decoded["schema_version"] != SCHEMA_MANIFEST_VERSION:
        raise ValueError("unsupported Codex schema manifest")
    if decoded["codex_cli_version"] != CODEX_APP_SERVER_PROTOCOL_VERSION:
        raise ValueError("Codex schema version is not the pinned protocol")
    require_sha256(decoded["complete_v2_bundle_sha256"], "complete schema bundle identity")
    if not isinstance(decoded["files"], dict) or not decoded["files"]:
        raise ValueError("Codex schema manifest has no files")
    for relative, expected in sorted(decoded["files"].items()):
        if (
            not isinstance(relative, str)
            or relative.startswith(("/", "\\"))
            or ".." in relative.split("/")
            or "\\" in relative
        ):
            raise ValueError("Codex schema manifest contains an invalid path")
        require_sha256(expected, f"schema identity for {relative}")
        actual = sha256_bytes(_schema_root().joinpath(relative).read_bytes())
        if actual != expected:
            raise ValueError(f"packaged Codex schema identity mismatch: {relative}")
    thread_schema = strict_json_loads(
        _schema_root().joinpath("v2/ThreadStartParams.json").read_bytes(),
        label="ThreadStartParams schema",
    )
    sandbox_values = thread_schema["definitions"]["SandboxMode"]["enum"]
    if sandbox_values != ["read-only", "workspace-write", "danger-full-access"]:
        raise ValueError("pinned Codex sandbox vocabulary changed")
    return decoded


def protocol_schema_identity() -> str:
    """Identity of the complete generated bundle plus every packaged schema byte."""

    manifest = schema_manifest()
    return fingerprint(
        {
            "codex_cli_version": manifest["codex_cli_version"],
            "complete_v2_bundle_sha256": manifest["complete_v2_bundle_sha256"],
            "files": manifest["files"],
        }
    )


@lru_cache(maxsize=32)
def load_schema(relative: str) -> Mapping[str, Any]:
    manifest = schema_manifest()
    if relative not in manifest["files"]:
        raise ValueError(f"schema is outside the pinned lifecycle subset: {relative}")
    value = strict_json_loads(
        _schema_root().joinpath(relative).read_bytes(),
        label=f"Codex schema {relative}",
    )
    if not isinstance(value, dict):
        raise ValueError(f"Codex schema is not an object: {relative}")
    return value


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ValueError(f"unsupported JSON Schema type: {expected}")


def _resolve_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"external JSON Schema reference refused: {reference}")
    target: Any = root
    for component in reference[2:].split("/"):
        key = component.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, Mapping) or key not in target:
            raise ValueError(f"unresolved JSON Schema reference: {reference}")
        target = target[key]
    if not isinstance(target, Mapping):
        raise ValueError(f"JSON Schema reference is not an object: {reference}")
    return target


def _validate(schema: Mapping[str, Any] | bool, value: Any, root: Mapping[str, Any], path: str) -> None:
    if schema is True:
        return
    if schema is False:
        raise ValueError(f"{path} is forbidden by its JSON Schema")
    if not isinstance(schema, Mapping):
        raise ValueError(f"{path} has a malformed JSON Schema")
    if "$ref" in schema:
        _validate(_resolve_ref(root, schema["$ref"]), value, root, path)
        return
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} does not match the schema constant")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is outside the schema enum")
    if "allOf" in schema:
        for choice in schema["allOf"]:
            _validate(choice, value, root, path)
    if "anyOf" in schema:
        errors = []
        for choice in schema["anyOf"]:
            try:
                _validate(choice, value, root, path)
                break
            except ValueError as error:
                errors.append(error)
        else:
            raise ValueError(f"{path} matches no anyOf branch") from errors[-1]
    if "oneOf" in schema:
        matches = 0
        last_error: ValueError | None = None
        for choice in schema["oneOf"]:
            try:
                _validate(choice, value, root, path)
                matches += 1
            except ValueError as error:
                last_error = error
        if matches != 1:
            raise ValueError(f"{path} does not match exactly one oneOf branch") from last_error

    expected = schema.get("type")
    if expected is not None:
        allowed = [expected] if isinstance(expected, str) else expected
        if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
            raise ValueError(f"{path} has an unsupported schema type declaration")
        if not any(_matches_type(value, item) for item in allowed):
            raise ValueError(f"{path} has the wrong JSON type")
    if "format" in schema:
        integer_ranges = {
            "uint": (0, 2**64 - 1),
            "uint16": (0, 2**16 - 1),
            "uint32": (0, 2**32 - 1),
            "uint64": (0, 2**64 - 1),
            "int32": (-(2**31), 2**31 - 1),
            "int64": (-(2**63), 2**63 - 1),
        }
        schema_format = schema["format"]
        if schema_format not in integer_ranges:
            raise ValueError(f"{path} uses unsupported JSON Schema format: {schema_format}")
        lower, upper = integer_ranges[schema_format]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not lower <= value <= upper
        ):
            raise ValueError(f"{path} is outside its {schema_format} range")

    if isinstance(value, dict):
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise ValueError(f"{path} has malformed schema requirements")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"{path} is missing required fields: {sorted(missing)}")
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise ValueError(f"{path} has malformed schema properties")
        for key, item in value.items():
            child = properties.get(key)
            if child is not None:
                _validate(child, item, root, f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                raise ValueError(f"{path} contains unknown field: {key}")
            elif isinstance(schema.get("additionalProperties"), Mapping):
                _validate(schema["additionalProperties"], item, root, f"{path}.{key}")

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None and len(value) < minimum:
            raise ValueError(f"{path} has too few items")
        if maximum is not None and len(value) > maximum:
            raise ValueError(f"{path} has too many items")
        if schema.get("uniqueItems") and len({canonical_bytes(item) for item in value}) != len(value):
            raise ValueError(f"{path} contains duplicate items")
        items = schema.get("items")
        if isinstance(items, Mapping):
            for index, item in enumerate(value):
                _validate(items, item, root, f"{path}[{index}]")

    if isinstance(value, str):
        encoded_length = len(value)
        if "minLength" in schema and encoded_length < schema["minLength"]:
            raise ValueError(f"{path} is too short")
        if "maxLength" in schema and encoded_length > schema["maxLength"]:
            raise ValueError(f"{path} is too long")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValueError(f"{path} does not match its schema pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} is below its schema minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} is above its schema maximum")


def validate_schema(relative: str, value: Any, *, label: str | None = None) -> None:
    schema = load_schema(relative)
    _validate(schema, value, schema, label or relative)
