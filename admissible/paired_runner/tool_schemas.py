"""Strict versioned request and result records for the four M1 tools.

These records are representation-only.  They describe what a future runtime
may propose or report; they never open a file, spawn a process, or apply a
mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from .canonical import Fingerprint, fingerprint
from .schemas import (
    SCHEMA_LIST_FILES_REQUEST,
    SCHEMA_LIST_FILES_RESULT,
    SCHEMA_READ_FILE_REQUEST,
    SCHEMA_READ_FILE_RESULT,
    SCHEMA_RUN_COMMAND_REQUEST,
    SCHEMA_RUN_COMMAND_RESULT,
    SCHEMA_VERSION,
    SCHEMA_WRITE_FILE_REQUEST,
    SCHEMA_WRITE_FILE_RESULT,
)


MAX_PATH_BYTES = 4096
MAX_CONTENT_BYTES = 1_048_576
MAX_ENTRIES = 10_000
MAX_LINES = 10_000
MAX_START_LINE = 1_000_000
MAX_ARGV_ITEMS = 128
MAX_ARG_BYTES = 4096
MAX_ARGV_TOTAL_BYTES = 65_536
MAX_COMMAND_TIMEOUT_MS = 60_000
MAX_OUTPUT_BYTES = 1_048_576
PROCESS_EXIT_MIN = -128
PROCESS_EXIT_MAX = 255

TOOL_OUTCOMES = frozenset({"OK", "REFUSED", "FAILED"})
REQUEST_FINGERPRINT_DOMAINS = {
    "list_files": f"{SCHEMA_LIST_FILES_REQUEST}.fingerprint",
    "read_file": f"{SCHEMA_READ_FILE_REQUEST}.fingerprint",
    "write_file": f"{SCHEMA_WRITE_FILE_REQUEST}.fingerprint",
    "run_command": f"{SCHEMA_RUN_COMMAND_REQUEST}.fingerprint",
}
RESULT_FINGERPRINT_DOMAINS = {
    "list_files": f"{SCHEMA_LIST_FILES_RESULT}.fingerprint",
    "read_file": f"{SCHEMA_READ_FILE_RESULT}.fingerprint",
    "write_file": f"{SCHEMA_WRITE_FILE_RESULT}.fingerprint",
    "run_command": f"{SCHEMA_RUN_COMMAND_RESULT}.fingerprint",
}


def _strict_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _bounded_text(value: Any, label: str, *, maximum_bytes: int, allow_nul: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if not allow_nul and "\x00" in value:
        raise ValueError(f"{label} must not contain NUL")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must be valid UTF-8") from error
    if size > maximum_bytes:
        raise ValueError(f"{label} exceeds its {maximum_bytes}-byte bound")
    return value


def _relative_posix_path(value: Any, label: str = "path") -> str:
    value = _bounded_text(value, label, maximum_bytes=MAX_PATH_BYTES)
    if value == ".":
        return value
    if (
        not value
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "//" in value
        or ":" in value
    ):
        raise ValueError(f"{label} must be a relative POSIX path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError(f"{label} contains an ambiguous path segment")
    return value


def _fingerprint(value: Any, label: str) -> Fingerprint:
    if not isinstance(value, Fingerprint):
        raise ValueError(f"{label} must be a Fingerprint")
    return value.validated()


def _optional_fingerprint(value: Any, label: str) -> Fingerprint | None:
    if value is None:
        return None
    return _fingerprint(value, label)


def _error_code(value: Any, label: str = "error_code") -> str | None:
    if value is None:
        return None
    value = _bounded_text(value, label, maximum_bytes=128)
    if not value or any(character.isspace() for character in value):
        raise ValueError(f"{label} must be a compact non-empty code")
    return value


def _exact_fields(data: Any, required: set[str], optional: set[str], label: str) -> None:
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be an object")
    present = set(data)
    allowed = required | optional
    if not required <= present or not present <= allowed:
        missing = sorted(required - present)
        extra = sorted(present - allowed)
        raise ValueError(f"{label} fields are not exact (missing={missing}, extra={extra})")


def _schema_fields(data: Any, schema_id: str, required: set[str], optional: set[str], label: str) -> None:
    _exact_fields(data, required, optional, label)
    if data["schema_id"] != schema_id or data["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported {label} schema")


def _request_body(request: "ToolRequest") -> dict[str, Any]:
    return request._body_without_fingerprint()


def _result_body(result: "ToolResult") -> dict[str, Any]:
    return result._body_without_fingerprint()


class ToolRequest:
    """Base type for the closed request union carried by CanonicalProposal."""

    tool_name: ClassVar[str]
    schema_id: str
    schema_version: int
    tool_grammar_fingerprint: Fingerprint
    request_fingerprint: Fingerprint

    @property
    def effect_classification(self) -> str:
        raise NotImplementedError

    def _body_without_fingerprint(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body_without_fingerprint(), "request_fingerprint": self.request_fingerprint.to_dict()}

    def validated(self) -> "ToolRequest":
        raise NotImplementedError


class ToolResult:
    """Base type for the closed result union of the four tools."""

    tool_name: ClassVar[str]
    schema_id: str
    schema_version: int
    request_fingerprint: Fingerprint
    outcome: str
    error_code: str | None
    result_fingerprint: Fingerprint

    def _body_without_fingerprint(self) -> dict[str, Any]:
        raise NotImplementedError

    def _validate_common(self, expected_schema: str) -> None:
        if self.schema_id != expected_schema or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported tool result schema")
        _fingerprint(self.request_fingerprint, "request_fingerprint")
        if self.request_fingerprint.domain != REQUEST_FINGERPRINT_DOMAINS[self.tool_name]:
            raise ValueError("tool result is bound to a request from another tool schema")
        if self.outcome not in TOOL_OUTCOMES:
            raise ValueError("tool result outcome must be OK, REFUSED, or FAILED")
        _error_code(self.error_code)
        if self.outcome == "OK" and self.error_code is not None:
            raise ValueError("successful tool result cannot carry an error code")
        if self.outcome != "OK" and self.error_code is None:
            raise ValueError("refused or failed tool result requires an error code")
        _fingerprint(self.result_fingerprint, "result_fingerprint")

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body_without_fingerprint(), "result_fingerprint": self.result_fingerprint.to_dict()}

    def validated(self) -> "ToolResult":
        raise NotImplementedError


@dataclass(frozen=True)
class ListFilesRequest(ToolRequest):
    tool_name: ClassVar[str] = "list_files"
    effect_classification: ClassVar[str] = "READ_ONLY"
    schema_id: str
    schema_version: int
    tool_grammar_fingerprint: Fingerprint
    path: str
    recursive: bool
    max_entries: int
    request_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, tool_grammar_fingerprint: Fingerprint, path: str = ".", recursive: bool = False, max_entries: int = MAX_ENTRIES) -> "ListFilesRequest":
        body = {
            "schema_id": SCHEMA_LIST_FILES_REQUEST,
            "schema_version": SCHEMA_VERSION,
            "tool_grammar_fingerprint": tool_grammar_fingerprint.to_dict(),
            "path": path,
            "recursive": recursive,
            "max_entries": max_entries,
        }
        return cls(
            **{key: value for key, value in body.items() if key not in {"tool_grammar_fingerprint"}},
            tool_grammar_fingerprint=tool_grammar_fingerprint,
            request_fingerprint=fingerprint(body, domain=REQUEST_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "tool_grammar_fingerprint": self.tool_grammar_fingerprint.to_dict(),
            "path": self.path, "recursive": self.recursive, "max_entries": self.max_entries,
        }

    def validated(self) -> "ListFilesRequest":
        if self.schema_id != SCHEMA_LIST_FILES_REQUEST or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported list_files request schema")
        _fingerprint(self.tool_grammar_fingerprint, "tool_grammar_fingerprint")
        _relative_posix_path(self.path)
        _strict_bool(self.recursive, "recursive")
        _strict_int(self.max_entries, "max_entries", minimum=1, maximum=MAX_ENTRIES)
        _fingerprint(self.request_fingerprint, "request_fingerprint")
        if self.request_fingerprint.domain != REQUEST_FINGERPRINT_DOMAINS[self.tool_name] or fingerprint(_request_body(self), domain=self.request_fingerprint.domain) != self.request_fingerprint:
            raise ValueError("list_files request fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "ListFilesRequest":
        required = {"schema_id", "schema_version", "tool_grammar_fingerprint", "path", "recursive", "max_entries", "request_fingerprint"}
        _schema_fields(data, SCHEMA_LIST_FILES_REQUEST, required, set(), "list_files request")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            tool_grammar_fingerprint=_fingerprint_from_dict(data["tool_grammar_fingerprint"], "tool_grammar_fingerprint"),
            path=data["path"], recursive=data["recursive"], max_entries=data["max_entries"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ReadFileRequest(ToolRequest):
    tool_name: ClassVar[str] = "read_file"
    effect_classification: ClassVar[str] = "READ_ONLY"
    schema_id: str
    schema_version: int
    tool_grammar_fingerprint: Fingerprint
    path: str
    start_line: int | None
    max_lines: int
    request_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, tool_grammar_fingerprint: Fingerprint, path: str, start_line: int | None = None, max_lines: int = MAX_LINES) -> "ReadFileRequest":
        body = {
            "schema_id": SCHEMA_READ_FILE_REQUEST, "schema_version": SCHEMA_VERSION,
            "tool_grammar_fingerprint": tool_grammar_fingerprint.to_dict(), "path": path,
            "start_line": start_line, "max_lines": max_lines,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"],
            tool_grammar_fingerprint=tool_grammar_fingerprint, path=path, start_line=start_line,
            max_lines=max_lines, request_fingerprint=fingerprint(body, domain=REQUEST_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "tool_grammar_fingerprint": self.tool_grammar_fingerprint.to_dict(), "path": self.path,
            "start_line": self.start_line, "max_lines": self.max_lines,
        }

    def validated(self) -> "ReadFileRequest":
        if self.schema_id != SCHEMA_READ_FILE_REQUEST or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported read_file request schema")
        _fingerprint(self.tool_grammar_fingerprint, "tool_grammar_fingerprint")
        _relative_posix_path(self.path)
        if self.start_line is not None:
            _strict_int(self.start_line, "start_line", minimum=1, maximum=MAX_START_LINE)
        _strict_int(self.max_lines, "max_lines", minimum=1, maximum=MAX_LINES)
        _fingerprint(self.request_fingerprint, "request_fingerprint")
        if self.request_fingerprint.domain != REQUEST_FINGERPRINT_DOMAINS[self.tool_name] or fingerprint(_request_body(self), domain=self.request_fingerprint.domain) != self.request_fingerprint:
            raise ValueError("read_file request fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "ReadFileRequest":
        required = {"schema_id", "schema_version", "tool_grammar_fingerprint", "path", "max_lines", "request_fingerprint"}
        _schema_fields(data, SCHEMA_READ_FILE_REQUEST, required, {"start_line"}, "read_file request")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            tool_grammar_fingerprint=_fingerprint_from_dict(data["tool_grammar_fingerprint"], "tool_grammar_fingerprint"),
            path=data["path"], start_line=data.get("start_line"), max_lines=data["max_lines"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class WriteFileRequest(ToolRequest):
    tool_name: ClassVar[str] = "write_file"
    effect_classification: ClassVar[str] = "FILE_MUTATION"
    schema_id: str
    schema_version: int
    tool_grammar_fingerprint: Fingerprint
    path: str
    content: str
    create_parents: bool
    request_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, tool_grammar_fingerprint: Fingerprint, path: str, content: str, create_parents: bool = False) -> "WriteFileRequest":
        body = {
            "schema_id": SCHEMA_WRITE_FILE_REQUEST, "schema_version": SCHEMA_VERSION,
            "tool_grammar_fingerprint": tool_grammar_fingerprint.to_dict(), "path": path,
            "content": content, "create_parents": create_parents,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"],
            tool_grammar_fingerprint=tool_grammar_fingerprint, path=path, content=content,
            create_parents=create_parents, request_fingerprint=fingerprint(body, domain=REQUEST_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "tool_grammar_fingerprint": self.tool_grammar_fingerprint.to_dict(), "path": self.path,
            "content": self.content, "create_parents": self.create_parents,
        }

    def validated(self) -> "WriteFileRequest":
        if self.schema_id != SCHEMA_WRITE_FILE_REQUEST or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported write_file request schema")
        _fingerprint(self.tool_grammar_fingerprint, "tool_grammar_fingerprint")
        _relative_posix_path(self.path)
        _bounded_text(self.content, "content", maximum_bytes=MAX_CONTENT_BYTES)
        _strict_bool(self.create_parents, "create_parents")
        _fingerprint(self.request_fingerprint, "request_fingerprint")
        if self.request_fingerprint.domain != REQUEST_FINGERPRINT_DOMAINS[self.tool_name] or fingerprint(_request_body(self), domain=self.request_fingerprint.domain) != self.request_fingerprint:
            raise ValueError("write_file request fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "WriteFileRequest":
        required = {"schema_id", "schema_version", "tool_grammar_fingerprint", "path", "content", "request_fingerprint"}
        _schema_fields(data, SCHEMA_WRITE_FILE_REQUEST, required, {"create_parents"}, "write_file request")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            tool_grammar_fingerprint=_fingerprint_from_dict(data["tool_grammar_fingerprint"], "tool_grammar_fingerprint"),
            path=data["path"], content=data["content"], create_parents=data.get("create_parents", False),
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class RunCommandRequest(ToolRequest):
    tool_name: ClassVar[str] = "run_command"
    effect_classification: ClassVar[str] = "PROCESS_EXECUTION"
    schema_id: str
    schema_version: int
    tool_grammar_fingerprint: Fingerprint
    argv: tuple[str, ...]
    cwd: str
    timeout_ms: int
    max_output_bytes: int
    request_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, tool_grammar_fingerprint: Fingerprint, argv: tuple[str, ...] | list[str], cwd: str = ".", timeout_ms: int = MAX_COMMAND_TIMEOUT_MS, max_output_bytes: int = MAX_OUTPUT_BYTES) -> "RunCommandRequest":
        argv_tuple = tuple(argv) if isinstance(argv, (tuple, list)) else argv
        body = {
            "schema_id": SCHEMA_RUN_COMMAND_REQUEST, "schema_version": SCHEMA_VERSION,
            "tool_grammar_fingerprint": tool_grammar_fingerprint.to_dict(), "argv": list(argv_tuple),
            "cwd": cwd, "timeout_ms": timeout_ms, "max_output_bytes": max_output_bytes,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"],
            tool_grammar_fingerprint=tool_grammar_fingerprint, argv=argv_tuple, cwd=cwd,
            timeout_ms=timeout_ms, max_output_bytes=max_output_bytes,
            request_fingerprint=fingerprint(body, domain=REQUEST_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "tool_grammar_fingerprint": self.tool_grammar_fingerprint.to_dict(), "argv": list(self.argv),
            "cwd": self.cwd, "timeout_ms": self.timeout_ms, "max_output_bytes": self.max_output_bytes,
        }

    def validated(self) -> "RunCommandRequest":
        if self.schema_id != SCHEMA_RUN_COMMAND_REQUEST or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported run_command request schema")
        _fingerprint(self.tool_grammar_fingerprint, "tool_grammar_fingerprint")
        if not isinstance(self.argv, tuple) or not 1 <= len(self.argv) <= MAX_ARGV_ITEMS:
            raise ValueError("argv must be a tuple with 1 to 128 items")
        total = 0
        for item in self.argv:
            _bounded_text(item, "argv item", maximum_bytes=MAX_ARG_BYTES)
            total += len(item.encode("utf-8"))
        if total > MAX_ARGV_TOTAL_BYTES:
            raise ValueError("argv exceeds its total byte bound")
        _relative_posix_path(self.cwd, "cwd")
        _strict_int(self.timeout_ms, "timeout_ms", minimum=1, maximum=MAX_COMMAND_TIMEOUT_MS)
        _strict_int(self.max_output_bytes, "max_output_bytes", minimum=1, maximum=MAX_OUTPUT_BYTES)
        _fingerprint(self.request_fingerprint, "request_fingerprint")
        if self.request_fingerprint.domain != REQUEST_FINGERPRINT_DOMAINS[self.tool_name] or fingerprint(_request_body(self), domain=self.request_fingerprint.domain) != self.request_fingerprint:
            raise ValueError("run_command request fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "RunCommandRequest":
        required = {"schema_id", "schema_version", "tool_grammar_fingerprint", "argv", "cwd", "timeout_ms", "max_output_bytes", "request_fingerprint"}
        _schema_fields(data, SCHEMA_RUN_COMMAND_REQUEST, required, set(), "run_command request")
        if not isinstance(data["argv"], list):
            raise ValueError("argv must be an array")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            tool_grammar_fingerprint=_fingerprint_from_dict(data["tool_grammar_fingerprint"], "tool_grammar_fingerprint"),
            argv=tuple(data["argv"]), cwd=data["cwd"], timeout_ms=data["timeout_ms"],
            max_output_bytes=data["max_output_bytes"], request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ListFilesResult(ToolResult):
    tool_name: ClassVar[str] = "list_files"
    schema_id: str
    schema_version: int
    request_fingerprint: Fingerprint
    outcome: str
    entries: tuple[str, ...]
    truncated: bool
    error_code: str | None
    result_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, request_fingerprint: Fingerprint, outcome: str = "OK", entries: tuple[str, ...] | list[str] = (), truncated: bool = False, error_code: str | None = None) -> "ListFilesResult":
        entries_tuple = tuple(entries) if isinstance(entries, (tuple, list)) else entries
        body = {
            "schema_id": SCHEMA_LIST_FILES_RESULT, "schema_version": SCHEMA_VERSION,
            "request_fingerprint": request_fingerprint.to_dict(), "outcome": outcome,
            "entries": list(entries_tuple), "truncated": truncated, "error_code": error_code,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"], request_fingerprint=request_fingerprint,
            outcome=outcome, entries=entries_tuple, truncated=truncated, error_code=error_code,
            result_fingerprint=fingerprint(body, domain=RESULT_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "request_fingerprint": self.request_fingerprint.to_dict(), "outcome": self.outcome,
            "entries": list(self.entries), "truncated": self.truncated, "error_code": self.error_code,
        }

    def validated(self) -> "ListFilesResult":
        self._validate_common(SCHEMA_LIST_FILES_RESULT)
        if not isinstance(self.entries, tuple) or len(self.entries) > MAX_ENTRIES:
            raise ValueError("entries must contain at most 10000 paths")
        validated_entries = tuple(_relative_posix_path(path, "entry") for path in self.entries)
        if validated_entries != tuple(sorted(validated_entries)) or len(set(validated_entries)) != len(validated_entries):
            raise ValueError("entries must be sorted and unique")
        _strict_bool(self.truncated, "truncated")
        if self.outcome != "OK" and (self.entries or self.truncated):
            raise ValueError("refused or failed list_files result cannot contain entries")
        if RESULT_FINGERPRINT_DOMAINS[self.tool_name] != self.result_fingerprint.domain or fingerprint(_result_body(self), domain=self.result_fingerprint.domain) != self.result_fingerprint:
            raise ValueError("list_files result fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "ListFilesResult":
        required = {"schema_id", "schema_version", "request_fingerprint", "outcome", "entries", "truncated", "result_fingerprint"}
        _schema_fields(data, SCHEMA_LIST_FILES_RESULT, required, {"error_code"}, "list_files result")
        if not isinstance(data["entries"], list):
            raise ValueError("entries must be an array")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"),
            outcome=data["outcome"], entries=tuple(data["entries"]), truncated=data["truncated"],
            error_code=data.get("error_code"), result_fingerprint=_fingerprint_from_dict(data["result_fingerprint"], "result_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ReadFileResult(ToolResult):
    tool_name: ClassVar[str] = "read_file"
    schema_id: str
    schema_version: int
    request_fingerprint: Fingerprint
    outcome: str
    content: str
    bytes_read: int
    truncated: bool
    error_code: str | None
    result_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, request_fingerprint: Fingerprint, outcome: str = "OK", content: str = "", bytes_read: int | None = None, truncated: bool = False, error_code: str | None = None) -> "ReadFileResult":
        if bytes_read is None:
            bytes_read = len(content.encode("utf-8"))
        body = {
            "schema_id": SCHEMA_READ_FILE_RESULT, "schema_version": SCHEMA_VERSION,
            "request_fingerprint": request_fingerprint.to_dict(), "outcome": outcome, "content": content,
            "bytes_read": bytes_read, "truncated": truncated, "error_code": error_code,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"], request_fingerprint=request_fingerprint,
            outcome=outcome, content=content, bytes_read=bytes_read, truncated=truncated, error_code=error_code,
            result_fingerprint=fingerprint(body, domain=RESULT_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "request_fingerprint": self.request_fingerprint.to_dict(), "outcome": self.outcome,
            "content": self.content, "bytes_read": self.bytes_read, "truncated": self.truncated,
            "error_code": self.error_code,
        }

    def validated(self) -> "ReadFileResult":
        self._validate_common(SCHEMA_READ_FILE_RESULT)
        _bounded_text(self.content, "content", maximum_bytes=MAX_CONTENT_BYTES)
        _strict_int(self.bytes_read, "bytes_read", minimum=0, maximum=MAX_CONTENT_BYTES)
        _strict_bool(self.truncated, "truncated")
        if self.outcome == "OK" and self.bytes_read != len(self.content.encode("utf-8")):
            raise ValueError("bytes_read must equal encoded content length")
        if self.outcome != "OK" and (self.content or self.bytes_read or self.truncated):
            raise ValueError("refused or failed read_file result cannot contain content")
        if RESULT_FINGERPRINT_DOMAINS[self.tool_name] != self.result_fingerprint.domain or fingerprint(_result_body(self), domain=self.result_fingerprint.domain) != self.result_fingerprint:
            raise ValueError("read_file result fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "ReadFileResult":
        required = {"schema_id", "schema_version", "request_fingerprint", "outcome", "content", "bytes_read", "truncated", "result_fingerprint"}
        _schema_fields(data, SCHEMA_READ_FILE_RESULT, required, {"error_code"}, "read_file result")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"),
            outcome=data["outcome"], content=data["content"], bytes_read=data["bytes_read"], truncated=data["truncated"],
            error_code=data.get("error_code"), result_fingerprint=_fingerprint_from_dict(data["result_fingerprint"], "result_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class WriteFileResult(ToolResult):
    tool_name: ClassVar[str] = "write_file"
    schema_id: str
    schema_version: int
    request_fingerprint: Fingerprint
    outcome: str
    bytes_written: int
    written_content_fingerprint: Fingerprint | None
    error_code: str | None
    result_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, request_fingerprint: Fingerprint, outcome: str = "OK", bytes_written: int = 0, written_content_fingerprint: Fingerprint | None = None, error_code: str | None = None) -> "WriteFileResult":
        body = {
            "schema_id": SCHEMA_WRITE_FILE_RESULT, "schema_version": SCHEMA_VERSION,
            "request_fingerprint": request_fingerprint.to_dict(), "outcome": outcome,
            "bytes_written": bytes_written,
            "written_content_fingerprint": written_content_fingerprint.to_dict() if written_content_fingerprint else None,
            "error_code": error_code,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"], request_fingerprint=request_fingerprint,
            outcome=outcome, bytes_written=bytes_written, written_content_fingerprint=written_content_fingerprint,
            error_code=error_code, result_fingerprint=fingerprint(body, domain=RESULT_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "request_fingerprint": self.request_fingerprint.to_dict(), "outcome": self.outcome,
            "bytes_written": self.bytes_written,
            "written_content_fingerprint": self.written_content_fingerprint.to_dict() if self.written_content_fingerprint else None,
            "error_code": self.error_code,
        }

    def validated(self) -> "WriteFileResult":
        self._validate_common(SCHEMA_WRITE_FILE_RESULT)
        _strict_int(self.bytes_written, "bytes_written", minimum=0, maximum=MAX_CONTENT_BYTES)
        _optional_fingerprint(self.written_content_fingerprint, "written_content_fingerprint")
        if self.outcome == "OK":
            if self.written_content_fingerprint is None:
                raise ValueError("successful write_file result requires written content fingerprint")
        elif self.bytes_written != 0 or self.written_content_fingerprint is not None:
            raise ValueError("refused or failed write_file result cannot claim written bytes")
        if RESULT_FINGERPRINT_DOMAINS[self.tool_name] != self.result_fingerprint.domain or fingerprint(_result_body(self), domain=self.result_fingerprint.domain) != self.result_fingerprint:
            raise ValueError("write_file result fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "WriteFileResult":
        required = {"schema_id", "schema_version", "request_fingerprint", "outcome", "bytes_written", "result_fingerprint"}
        _schema_fields(data, SCHEMA_WRITE_FILE_RESULT, required, {"written_content_fingerprint", "error_code"}, "write_file result")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"), outcome=data["outcome"],
            bytes_written=data["bytes_written"], written_content_fingerprint=_optional_fingerprint_from_dict(data.get("written_content_fingerprint"), "written_content_fingerprint"),
            error_code=data.get("error_code"), result_fingerprint=_fingerprint_from_dict(data["result_fingerprint"], "result_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class RunCommandResult(ToolResult):
    tool_name: ClassVar[str] = "run_command"
    schema_id: str
    schema_version: int
    request_fingerprint: Fingerprint
    outcome: str
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    exit_code: int | None
    error_code: str | None
    result_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, request_fingerprint: Fingerprint, outcome: str = "OK", stdout: str = "", stderr: str = "", stdout_truncated: bool = False, stderr_truncated: bool = False, exit_code: int | None = 0, error_code: str | None = None) -> "RunCommandResult":
        body = {
            "schema_id": SCHEMA_RUN_COMMAND_RESULT, "schema_version": SCHEMA_VERSION,
            "request_fingerprint": request_fingerprint.to_dict(), "outcome": outcome,
            "stdout": stdout, "stderr": stderr, "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated, "exit_code": exit_code, "error_code": error_code,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"], request_fingerprint=request_fingerprint,
            outcome=outcome, stdout=stdout, stderr=stderr, stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated, exit_code=exit_code, error_code=error_code,
            result_fingerprint=fingerprint(body, domain=RESULT_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "request_fingerprint": self.request_fingerprint.to_dict(), "outcome": self.outcome,
            "stdout": self.stdout, "stderr": self.stderr, "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated, "exit_code": self.exit_code, "error_code": self.error_code,
        }

    def validated(self) -> "RunCommandResult":
        self._validate_common(SCHEMA_RUN_COMMAND_RESULT)
        _bounded_text(self.stdout, "stdout", maximum_bytes=MAX_OUTPUT_BYTES, allow_nul=True)
        _bounded_text(self.stderr, "stderr", maximum_bytes=MAX_OUTPUT_BYTES, allow_nul=True)
        _strict_bool(self.stdout_truncated, "stdout_truncated")
        _strict_bool(self.stderr_truncated, "stderr_truncated")
        if self.exit_code is not None:
            _strict_int(self.exit_code, "exit_code", minimum=PROCESS_EXIT_MIN, maximum=PROCESS_EXIT_MAX)
        if self.outcome == "OK" and self.exit_code is None:
            raise ValueError("successful run_command result requires an exit code")
        if self.outcome == "REFUSED" and (self.stdout or self.stderr or self.stdout_truncated or self.stderr_truncated or self.exit_code is not None):
            raise ValueError("refused run_command result cannot contain process output")
        if RESULT_FINGERPRINT_DOMAINS[self.tool_name] != self.result_fingerprint.domain or fingerprint(_result_body(self), domain=self.result_fingerprint.domain) != self.result_fingerprint:
            raise ValueError("run_command result fingerprint mismatch")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "RunCommandResult":
        required = {"schema_id", "schema_version", "request_fingerprint", "outcome", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "result_fingerprint"}
        _schema_fields(data, SCHEMA_RUN_COMMAND_RESULT, required, {"exit_code", "error_code"}, "run_command result")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"), outcome=data["outcome"],
            stdout=data["stdout"], stderr=data["stderr"], stdout_truncated=data["stdout_truncated"], stderr_truncated=data["stderr_truncated"],
            exit_code=data.get("exit_code"), error_code=data.get("error_code"), result_fingerprint=_fingerprint_from_dict(data["result_fingerprint"], "result_fingerprint"),
        ).validated()


def _fingerprint_from_dict(value: Any, label: str) -> Fingerprint:
    return Fingerprint.from_dict(value, label=label)


def _optional_fingerprint_from_dict(value: Any, label: str) -> Fingerprint | None:
    if value is None:
        return None
    return _fingerprint_from_dict(value, label)


REQUEST_TYPES = {
    "list_files": ListFilesRequest,
    "read_file": ReadFileRequest,
    "write_file": WriteFileRequest,
    "run_command": RunCommandRequest,
}
RESULT_TYPES = {
    "list_files": ListFilesResult,
    "read_file": ReadFileResult,
    "write_file": WriteFileResult,
    "run_command": RunCommandResult,
}


def tool_request_from_dict(data: Any) -> ToolRequest:
    if not isinstance(data, dict):
        raise ValueError("tool request must be an object")
    schema_id = data.get("schema_id")
    dispatch = {
        SCHEMA_LIST_FILES_REQUEST: ListFilesRequest,
        SCHEMA_READ_FILE_REQUEST: ReadFileRequest,
        SCHEMA_WRITE_FILE_REQUEST: WriteFileRequest,
        SCHEMA_RUN_COMMAND_REQUEST: RunCommandRequest,
    }
    try:
        return dispatch[schema_id].from_dict(data)
    except KeyError as error:
        raise ValueError("unknown or missing tool request schema") from error


def tool_result_from_dict(data: Any) -> ToolResult:
    if not isinstance(data, dict):
        raise ValueError("tool result must be an object")
    dispatch = {
        SCHEMA_LIST_FILES_RESULT: ListFilesResult,
        SCHEMA_READ_FILE_RESULT: ReadFileResult,
        SCHEMA_WRITE_FILE_RESULT: WriteFileResult,
        SCHEMA_RUN_COMMAND_RESULT: RunCommandResult,
    }
    try:
        return dispatch[data.get("schema_id")].from_dict(data)
    except KeyError as error:
        raise ValueError("unknown or missing tool result schema") from error


__all__ = [
    "ListFilesRequest", "ListFilesResult", "ReadFileRequest", "ReadFileResult",
    "RunCommandRequest", "RunCommandResult", "ToolRequest", "ToolResult",
    "WriteFileRequest", "WriteFileResult", "tool_request_from_dict", "tool_result_from_dict",
    "MAX_ARGV_ITEMS", "MAX_ARGV_TOTAL_BYTES", "MAX_CONTENT_BYTES", "MAX_ENTRIES",
    "MAX_LINES", "MAX_OUTPUT_BYTES", "MAX_PATH_BYTES", "MAX_START_LINE",
]
