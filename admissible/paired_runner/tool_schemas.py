"""Strict versioned request and result records for the four M1 tools.

These records are representation-only.  They describe what a future runtime
may propose or report; they never open a file, spawn a process, or apply a
mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from .canonical import Fingerprint, fingerprint, fingerprint_bytes
from .schemas import (
    SCHEMA_CATALOG,
    SCHEMA_LIST_FILES_REQUEST,
    SCHEMA_LIST_FILES_RESULT,
    SCHEMA_READ_FILE_REQUEST,
    SCHEMA_READ_FILE_RESULT,
    SCHEMA_RUN_COMMAND_REQUEST,
    SCHEMA_RUN_COMMAND_RESULT,
    SCHEMA_TOOL_GRAMMAR,
    SCHEMA_TOOL_GRAMMAR_ENTRY,
    SCHEMA_VERSION,
    SCHEMA_WRITE_FILE_REQUEST,
    SCHEMA_WRITE_FILE_RESULT,
    TOOL_EFFECT_CLASSIFICATIONS,
    TOOL_NAMES,
    TOOL_REQUEST_SCHEMA_IDS,
    TOOL_RESULT_SCHEMA_IDS,
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
WRITTEN_CONTENT_FINGERPRINT_DOMAIN = f"{SCHEMA_WRITE_FILE_REQUEST[: -len('.request')]}.written_content"
GRAMMAR_DESCRIPTOR_FINGERPRINT_DOMAIN = f"{SCHEMA_TOOL_GRAMMAR_ENTRY}.descriptor"
# One incomplete UTF-8 sequence (at most four bytes) may be dropped when a
# bounded stream is cut, so a truncated retention lands inside this window.
MAX_UTF8_SEQUENCE_BYTES = 4


def retained_line_count(content: str) -> int:
    """Count retained lines without inventing a trailing empty line."""

    if not content:
        return 0
    return content.count("\n") + (0 if content.endswith("\n") else 1)


def written_content_fingerprint(content: str) -> Fingerprint:
    """The only permitted fingerprint of exact written bytes."""

    if not isinstance(content, str):
        raise ValueError("written content must be a string")
    return fingerprint_bytes(content.encode("utf-8", "strict"), domain=WRITTEN_CONTENT_FINGERPRINT_DOMAIN)


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


def _grammar_fingerprint(value: Any, label: str = "tool_grammar_fingerprint") -> Fingerprint:
    """A request may only cite a fingerprint from the grammar-specification domain."""

    value = _fingerprint(value, label)
    if value.domain != f"{SCHEMA_TOOL_GRAMMAR}.fingerprint":
        raise ValueError(f"{label} must be an exact tool-grammar specification fingerprint")
    return value


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

    def _bind_exact_request(self, request: Any) -> "ToolRequest":
        """Prove that this result answers exactly *request* and nothing else."""

        if not isinstance(request, ToolRequest):
            raise ValueError("exact result validation requires a typed tool request")
        request.validated()
        self.validated()
        if request.tool_name != self.tool_name:
            raise ValueError("tool result and tool request belong to different tools")
        if request.request_fingerprint != self.request_fingerprint:
            raise ValueError("tool result is not bound to this exact request")
        return request

    def validate_for_request(self, request: "ToolRequest") -> "ToolResult":
        """Pure exact-request validation implemented by every result type."""

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
        _grammar_fingerprint(self.tool_grammar_fingerprint)
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
        _grammar_fingerprint(self.tool_grammar_fingerprint)
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
        _grammar_fingerprint(self.tool_grammar_fingerprint)
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
        if isinstance(argv, str):
            raise ValueError("argv is an explicit argument array; an implicit shell string is refused")
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
        _grammar_fingerprint(self.tool_grammar_fingerprint)
        if not isinstance(self.argv, tuple) or not 1 <= len(self.argv) <= MAX_ARGV_ITEMS:
            raise ValueError("argv must be a tuple with 1 to 128 items")
        total = 0
        for item in self.argv:
            _bounded_text(item, "argv item", maximum_bytes=MAX_ARG_BYTES)
            total += len(item.encode("utf-8"))
        if not self.argv[0]:
            raise ValueError("argv[0] must be a non-empty executable token")
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

    def validate_for_request(self, request: Any) -> "ListFilesResult":
        """Bind the exact ListFilesRequest, its entry bound, and its scope."""

        request = self._bind_exact_request(request)
        if len(self.entries) > request.max_entries:
            raise ValueError("list_files result exceeds the entry limit of its originating request")
        if self.truncated and len(self.entries) != request.max_entries:
            raise ValueError("list_files truncation is only reached at the request entry limit")
        for entry in self.entries:
            if request.path == ".":
                relative = entry
            elif entry.startswith(request.path + "/"):
                relative = entry[len(request.path) + 1 :]
            else:
                raise ValueError("list_files entry lies outside the exact requested path")
            if not request.recursive and "/" in relative:
                raise ValueError("a non-recursive list_files result cannot contain nested entries")
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

    def validate_for_request(self, request: Any) -> "ReadFileResult":
        """Bind the exact ReadFileRequest, its line bound, and truncation."""

        request = self._bind_exact_request(request)
        lines = retained_line_count(self.content)
        if lines > request.max_lines:
            raise ValueError("read_file result retains more lines than its originating request allows")
        if self.truncated and lines != request.max_lines and self.bytes_read != MAX_CONTENT_BYTES:
            raise ValueError("read_file truncation is only reached at the request line bound or the content cap")
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
        if self.written_content_fingerprint is not None and self.written_content_fingerprint.domain != WRITTEN_CONTENT_FINGERPRINT_DOMAIN:
            raise ValueError("written content fingerprint must use the fixed written-content domain")
        if self.outcome == "OK":
            if self.written_content_fingerprint is None:
                raise ValueError("successful write_file result requires written content fingerprint")
        elif self.bytes_written != 0 or self.written_content_fingerprint is not None:
            raise ValueError("refused or failed write_file result cannot claim written bytes")
        if RESULT_FINGERPRINT_DOMAINS[self.tool_name] != self.result_fingerprint.domain or fingerprint(_result_body(self), domain=self.result_fingerprint.domain) != self.result_fingerprint:
            raise ValueError("write_file result fingerprint mismatch")
        return self

    def validate_for_request(self, request: Any) -> "WriteFileResult":
        """Bind the exact WriteFileRequest bytes and their exact fingerprint."""

        request = self._bind_exact_request(request)
        if self.outcome != "OK":
            return self
        expected_bytes = len(request.content.encode("utf-8", "strict"))
        if self.bytes_written != expected_bytes:
            raise ValueError("successful write_file result must report the exact requested byte length")
        if self.written_content_fingerprint != written_content_fingerprint(request.content):
            raise ValueError("successful write_file result must fingerprint the exact requested bytes")
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
    process_started: bool
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    exit_code: int | None
    error_code: str | None
    result_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, request_fingerprint: Fingerprint, outcome: str = "OK", process_started: bool = True, stdout: str = "", stderr: str = "", stdout_truncated: bool = False, stderr_truncated: bool = False, exit_code: int | None = 0, error_code: str | None = None) -> "RunCommandResult":
        body = {
            "schema_id": SCHEMA_RUN_COMMAND_RESULT, "schema_version": SCHEMA_VERSION,
            "request_fingerprint": request_fingerprint.to_dict(), "outcome": outcome,
            "process_started": process_started,
            "stdout": stdout, "stderr": stderr, "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated, "exit_code": exit_code, "error_code": error_code,
        }
        return cls(
            schema_id=body["schema_id"], schema_version=body["schema_version"], request_fingerprint=request_fingerprint,
            outcome=outcome, process_started=process_started, stdout=stdout, stderr=stderr, stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated, exit_code=exit_code, error_code=error_code,
            result_fingerprint=fingerprint(body, domain=RESULT_FINGERPRINT_DOMAINS[cls.tool_name]),
        ).validated()

    def _body_without_fingerprint(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "request_fingerprint": self.request_fingerprint.to_dict(), "outcome": self.outcome,
            "process_started": self.process_started,
            "stdout": self.stdout, "stderr": self.stderr, "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated, "exit_code": self.exit_code, "error_code": self.error_code,
        }

    def validated(self) -> "RunCommandResult":
        self._validate_common(SCHEMA_RUN_COMMAND_RESULT)
        _bounded_text(self.stdout, "stdout", maximum_bytes=MAX_OUTPUT_BYTES, allow_nul=True)
        _bounded_text(self.stderr, "stderr", maximum_bytes=MAX_OUTPUT_BYTES, allow_nul=True)
        _strict_bool(self.process_started, "process_started")
        _strict_bool(self.stdout_truncated, "stdout_truncated")
        _strict_bool(self.stderr_truncated, "stderr_truncated")
        if self.exit_code is not None:
            _strict_int(self.exit_code, "exit_code", minimum=PROCESS_EXIT_MIN, maximum=PROCESS_EXIT_MAX)
        # Tool execution success and command exit status are separate facts: an
        # OK outcome means the tool ran the exact command, not that the command
        # exited zero.  Process observations exist only for a started process.
        if self.outcome == "OK" and not self.process_started:
            raise ValueError("a successful run_command result must have started the command")
        if self.outcome == "OK" and self.exit_code is None:
            raise ValueError("successful run_command result requires an exit code")
        if self.outcome == "REFUSED" and self.process_started:
            raise ValueError("a refused run_command result cannot have started a process")
        if not self.process_started and (
            self.stdout or self.stderr or self.stdout_truncated or self.stderr_truncated or self.exit_code is not None
        ):
            raise ValueError("a run_command result that never started the command cannot contain process observations")
        if RESULT_FINGERPRINT_DOMAINS[self.tool_name] != self.result_fingerprint.domain or fingerprint(_result_body(self), domain=self.result_fingerprint.domain) != self.result_fingerprint:
            raise ValueError("run_command result fingerprint mismatch")
        return self

    def validate_for_request(self, request: Any) -> "RunCommandResult":
        """Bind the exact RunCommandRequest and its output bound."""

        request = self._bind_exact_request(request)
        for label, text, truncated in (
            ("stdout", self.stdout, self.stdout_truncated),
            ("stderr", self.stderr, self.stderr_truncated),
        ):
            size = len(text.encode("utf-8", "strict"))
            if size > request.max_output_bytes:
                raise ValueError(f"run_command {label} exceeds the output bound of its originating request")
            if truncated and size <= request.max_output_bytes - MAX_UTF8_SEQUENCE_BYTES:
                raise ValueError(f"run_command {label} claims truncation below the request output bound")
        return self

    @classmethod
    def from_dict(cls, data: Any) -> "RunCommandResult":
        required = {"schema_id", "schema_version", "request_fingerprint", "outcome", "process_started", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "result_fingerprint"}
        _schema_fields(data, SCHEMA_RUN_COMMAND_RESULT, required, {"exit_code", "error_code"}, "run_command result")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            request_fingerprint=_fingerprint_from_dict(data["request_fingerprint"], "request_fingerprint"), outcome=data["outcome"],
            process_started=data["process_started"],
            stdout=data["stdout"], stderr=data["stderr"], stdout_truncated=data["stdout_truncated"], stderr_truncated=data["stderr_truncated"],
            exit_code=data.get("exit_code"), error_code=data.get("error_code"), result_fingerprint=_fingerprint_from_dict(data["result_fingerprint"], "result_fingerprint"),
        ).validated()


def _fingerprint_from_dict(value: Any, label: str) -> Fingerprint:
    return Fingerprint.from_dict(value, label=label)


def _optional_fingerprint_from_dict(value: Any, label: str) -> Fingerprint | None:
    if value is None:
        return None
    return _fingerprint_from_dict(value, label)


def _descriptor_fingerprint(schema_id: str) -> Fingerprint:
    """Fingerprint the exact machine-readable descriptor of one tool schema."""

    try:
        descriptor = SCHEMA_CATALOG[schema_id]
    except KeyError as error:
        raise ValueError(f"unknown tool schema {schema_id!r}") from error
    return fingerprint(descriptor.to_dict(), domain=GRAMMAR_DESCRIPTOR_FINGERPRINT_DOMAIN)


@dataclass(frozen=True)
class ToolGrammarEntry:
    """One machine-verifiable tool selection inside a grammar specification."""

    schema_id: str
    schema_version: int
    tool_name: str
    request_schema_id: str
    request_schema_version: int
    result_schema_id: str
    result_schema_version: int
    effect_classification: str
    request_descriptor_fingerprint: Fingerprint
    result_descriptor_fingerprint: Fingerprint
    entry_fingerprint: Fingerprint

    @classmethod
    def for_tool(cls, tool_name: str) -> "ToolGrammarEntry":
        if tool_name not in TOOL_NAMES:
            raise ValueError(f"unknown tool name {tool_name!r}")
        request_schema_id = TOOL_REQUEST_SCHEMA_IDS[tool_name]
        result_schema_id = TOOL_RESULT_SCHEMA_IDS[tool_name]
        request_descriptor = _descriptor_fingerprint(request_schema_id)
        result_descriptor = _descriptor_fingerprint(result_schema_id)
        return cls(
            schema_id=SCHEMA_TOOL_GRAMMAR_ENTRY,
            schema_version=SCHEMA_VERSION,
            tool_name=tool_name,
            request_schema_id=request_schema_id,
            request_schema_version=SCHEMA_CATALOG[request_schema_id].version,
            result_schema_id=result_schema_id,
            result_schema_version=SCHEMA_CATALOG[result_schema_id].version,
            effect_classification=TOOL_EFFECT_CLASSIFICATIONS[tool_name],
            request_descriptor_fingerprint=request_descriptor,
            result_descriptor_fingerprint=result_descriptor,
            entry_fingerprint=fingerprint(
                cls._body_of(
                    tool_name,
                    request_schema_id,
                    SCHEMA_CATALOG[request_schema_id].version,
                    result_schema_id,
                    SCHEMA_CATALOG[result_schema_id].version,
                    TOOL_EFFECT_CLASSIFICATIONS[tool_name],
                    request_descriptor,
                    result_descriptor,
                ),
                domain=f"{SCHEMA_TOOL_GRAMMAR_ENTRY}.fingerprint",
            ),
        ).validated()

    @staticmethod
    def _body_of(
        tool_name: str,
        request_schema_id: str,
        request_schema_version: int,
        result_schema_id: str,
        result_schema_version: int,
        effect_classification: str,
        request_descriptor_fingerprint: Fingerprint,
        result_descriptor_fingerprint: Fingerprint,
    ) -> dict[str, Any]:
        return {
            "schema_id": SCHEMA_TOOL_GRAMMAR_ENTRY,
            "schema_version": SCHEMA_VERSION,
            "tool_name": tool_name,
            "request_schema_id": request_schema_id,
            "request_schema_version": request_schema_version,
            "result_schema_id": result_schema_id,
            "result_schema_version": result_schema_version,
            "effect_classification": effect_classification,
            "request_descriptor_fingerprint": request_descriptor_fingerprint.to_dict(),
            "result_descriptor_fingerprint": result_descriptor_fingerprint.to_dict(),
        }

    def _body(self) -> dict[str, Any]:
        return self._body_of(
            self.tool_name,
            self.request_schema_id,
            self.request_schema_version,
            self.result_schema_id,
            self.result_schema_version,
            self.effect_classification,
            self.request_descriptor_fingerprint,
            self.result_descriptor_fingerprint,
        )

    def validated(self) -> "ToolGrammarEntry":
        if self.schema_id != SCHEMA_TOOL_GRAMMAR_ENTRY or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported tool grammar entry schema")
        if self.tool_name not in TOOL_NAMES:
            raise ValueError("tool grammar entry names an unknown tool")
        if self.request_schema_id != TOOL_REQUEST_SCHEMA_IDS[self.tool_name]:
            raise ValueError("tool grammar entry binds the wrong request schema")
        if self.result_schema_id != TOOL_RESULT_SCHEMA_IDS[self.tool_name]:
            raise ValueError("tool grammar entry binds the wrong result schema")
        if self.request_schema_version != SCHEMA_CATALOG[self.request_schema_id].version:
            raise ValueError("tool grammar entry binds an unavailable request schema version")
        if self.result_schema_version != SCHEMA_CATALOG[self.result_schema_id].version:
            raise ValueError("tool grammar entry binds an unavailable result schema version")
        if self.effect_classification != TOOL_EFFECT_CLASSIFICATIONS[self.tool_name]:
            raise ValueError("tool grammar entry declares the wrong effect classification")
        _fingerprint(self.request_descriptor_fingerprint, "request_descriptor_fingerprint")
        _fingerprint(self.result_descriptor_fingerprint, "result_descriptor_fingerprint")
        if self.request_descriptor_fingerprint != _descriptor_fingerprint(self.request_schema_id):
            raise ValueError("tool grammar entry request descriptor fingerprint does not match the exact schema")
        if self.result_descriptor_fingerprint != _descriptor_fingerprint(self.result_schema_id):
            raise ValueError("tool grammar entry result descriptor fingerprint does not match the exact schema")
        _fingerprint(self.entry_fingerprint, "entry_fingerprint")
        if fingerprint(self._body(), domain=f"{SCHEMA_TOOL_GRAMMAR_ENTRY}.fingerprint") != self.entry_fingerprint:
            raise ValueError("tool grammar entry fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "entry_fingerprint": self.entry_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "ToolGrammarEntry":
        required = {
            "schema_id", "schema_version", "tool_name", "request_schema_id", "request_schema_version",
            "result_schema_id", "result_schema_version", "effect_classification",
            "request_descriptor_fingerprint", "result_descriptor_fingerprint", "entry_fingerprint",
        }
        _schema_fields(data, SCHEMA_TOOL_GRAMMAR_ENTRY, required, set(), "tool grammar entry")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], tool_name=data["tool_name"],
            request_schema_id=data["request_schema_id"], request_schema_version=data["request_schema_version"],
            result_schema_id=data["result_schema_id"], result_schema_version=data["result_schema_version"],
            effect_classification=data["effect_classification"],
            request_descriptor_fingerprint=_fingerprint_from_dict(data["request_descriptor_fingerprint"], "request_descriptor_fingerprint"),
            result_descriptor_fingerprint=_fingerprint_from_dict(data["result_descriptor_fingerprint"], "result_descriptor_fingerprint"),
            entry_fingerprint=_fingerprint_from_dict(data["entry_fingerprint"], "entry_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ToolGrammarSpecification:
    """The exact grammar an experiment selects, not a label for one.

    The grammar names the four tools and binds, per tool, the exact request and
    result schema identity, schema version, effect classification, and the
    fingerprint of the machine-readable descriptor that carries that schema's
    fields and bounds.  Its canonical fingerprint is therefore a function of the
    selected schemas rather than an opaque identifier a request can invent.
    """

    schema_id: str
    schema_version: int
    grammar_id: str
    grammar_version: str
    tool_names: tuple[str, ...]
    entries: tuple[ToolGrammarEntry, ...]
    grammar_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, grammar_id: str = "paired-runner-four-tool-grammar", grammar_version: str = "v1") -> "ToolGrammarSpecification":
        tool_names = tuple(sorted(TOOL_NAMES))
        entries = tuple(ToolGrammarEntry.for_tool(name) for name in tool_names)
        body = cls._body_of(grammar_id, grammar_version, tool_names, entries)
        return cls(
            schema_id=SCHEMA_TOOL_GRAMMAR,
            schema_version=SCHEMA_VERSION,
            grammar_id=grammar_id,
            grammar_version=grammar_version,
            tool_names=tool_names,
            entries=entries,
            grammar_fingerprint=fingerprint(body, domain=f"{SCHEMA_TOOL_GRAMMAR}.fingerprint"),
        ).validated()

    @staticmethod
    def _body_of(
        grammar_id: str,
        grammar_version: str,
        tool_names: tuple[str, ...],
        entries: tuple[ToolGrammarEntry, ...],
    ) -> dict[str, Any]:
        return {
            "schema_id": SCHEMA_TOOL_GRAMMAR,
            "schema_version": SCHEMA_VERSION,
            "grammar_id": grammar_id,
            "grammar_version": grammar_version,
            "tool_names": list(tool_names),
            "entries": [entry.to_dict() for entry in entries],
        }

    def _body(self) -> dict[str, Any]:
        return self._body_of(self.grammar_id, self.grammar_version, self.tool_names, self.entries)

    def validated(self) -> "ToolGrammarSpecification":
        if self.schema_id != SCHEMA_TOOL_GRAMMAR or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported tool grammar specification schema")
        _bounded_text(self.grammar_id, "grammar_id", maximum_bytes=128)
        _bounded_text(self.grammar_version, "grammar_version", maximum_bytes=128)
        if not self.grammar_id or not self.grammar_version:
            raise ValueError("grammar identity and version must be non-empty")
        if not isinstance(self.tool_names, tuple) or self.tool_names != tuple(sorted(TOOL_NAMES)):
            raise ValueError("the grammar must select exactly the four frozen tool names in canonical order")
        if not isinstance(self.entries, tuple) or len(self.entries) != len(self.tool_names):
            raise ValueError("the grammar must contain exactly one entry per selected tool")
        for name, entry in zip(self.tool_names, self.entries):
            if not isinstance(entry, ToolGrammarEntry):
                raise ValueError("grammar entries must be typed tool grammar entries")
            entry.validated()
            if entry.tool_name != name:
                raise ValueError("grammar entries are not in canonical tool-name order")
        _fingerprint(self.grammar_fingerprint, "grammar_fingerprint")
        if self.grammar_fingerprint.domain != f"{SCHEMA_TOOL_GRAMMAR}.fingerprint":
            raise ValueError("grammar fingerprint has the wrong domain")
        if fingerprint(self._body(), domain=f"{SCHEMA_TOOL_GRAMMAR}.fingerprint") != self.grammar_fingerprint:
            raise ValueError("tool grammar specification fingerprint mismatch")
        return self

    def entry_for(self, tool_name: str) -> ToolGrammarEntry:
        for entry in self.entries:
            if entry.tool_name == tool_name:
                return entry
        raise ValueError(f"tool {tool_name!r} is absent from this exact grammar")

    def validate_request(self, request: Any) -> "ToolRequest":
        """Prove that *request* is exactly one of this grammar's selections."""

        if not isinstance(request, ToolRequest):
            raise ValueError("grammar validation requires a typed tool request")
        request.validated()
        self.validated()
        entry = self.entry_for(request.tool_name)
        if request.schema_id != entry.request_schema_id:
            raise ValueError("the request schema is absent from this exact grammar")
        if request.schema_version != entry.request_schema_version:
            raise ValueError("the request schema version is not permitted by this exact grammar")
        if request.effect_classification != entry.effect_classification:
            raise ValueError("the request effect classification differs from its grammar entry")
        if request.tool_grammar_fingerprint != self.grammar_fingerprint:
            raise ValueError("the request cites a different tool grammar specification")
        return request

    def validate_result(self, result: Any) -> "ToolResult":
        """Prove that *result* uses exactly this grammar's result schema."""

        if not isinstance(result, ToolResult):
            raise ValueError("grammar validation requires a typed tool result")
        result.validated()
        self.validated()
        entry = self.entry_for(result.tool_name)
        if result.schema_id != entry.result_schema_id:
            raise ValueError("the result schema is absent from this exact grammar")
        if result.schema_version != entry.result_schema_version:
            raise ValueError("the result schema version is not permitted by this exact grammar")
        return result

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "grammar_fingerprint": self.grammar_fingerprint.to_dict()}

    def normative_dict(self) -> dict[str, Any]:
        return self._body()

    @classmethod
    def from_dict(cls, data: Any) -> "ToolGrammarSpecification":
        required = {
            "schema_id", "schema_version", "grammar_id", "grammar_version", "tool_names", "entries",
            "grammar_fingerprint",
        }
        _schema_fields(data, SCHEMA_TOOL_GRAMMAR, required, set(), "tool grammar specification")
        if not isinstance(data["tool_names"], list) or not isinstance(data["entries"], list):
            raise ValueError("grammar tool names and entries must be arrays")
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], grammar_id=data["grammar_id"],
            grammar_version=data["grammar_version"], tool_names=tuple(data["tool_names"]),
            entries=tuple(ToolGrammarEntry.from_dict(item) for item in data["entries"]),
            grammar_fingerprint=_fingerprint_from_dict(data["grammar_fingerprint"], "grammar_fingerprint"),
        ).validated()


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
    "RunCommandRequest", "RunCommandResult", "ToolGrammarEntry", "ToolGrammarSpecification",
    "ToolRequest", "ToolResult",
    "WriteFileRequest", "WriteFileResult", "tool_request_from_dict", "tool_result_from_dict",
    "MAX_ARGV_ITEMS", "MAX_ARGV_TOTAL_BYTES", "MAX_CONTENT_BYTES", "MAX_ENTRIES",
    "MAX_LINES", "MAX_OUTPUT_BYTES", "MAX_PATH_BYTES", "MAX_START_LINE",
    "MAX_UTF8_SEQUENCE_BYTES", "WRITTEN_CONTENT_FINGERPRINT_DOMAIN",
    "retained_line_count", "written_content_fingerprint",
]
