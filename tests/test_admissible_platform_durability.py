"""Direct production-path regressions for the shared durability adapter."""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

import admissible.delegated_gate.durability as durability_module
from admissible.delegated_gate.durability import (
    CapabilityStep,
    FileContentDurability,
    FileDurableFlushFailure,
    FileFlushFailure,
    FileWriteFailure,
    MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH,
    PlatformDurabilityAdapter,
    PostPublicationFingerprintMismatch,
    PostPublicationReloadFailure,
    PublicationApiUnavailable,
    PublicationConflict,
    PublicationFailureBeforeVisibility,
    PublicationMetadataDurability,
    PublicationMode,
    PublicationVisibleButMetadataUncertain,
    ReplacementAuthority,
    SameVolumeRequired,
    TemporaryCleanupFailure,
    WINDOWS_MOVEFILEEX_PROFILE,
    WindowsMoveFileError,
    probe_platform_durability,
)
from admissible.delegated_gate.events import GateExecutionStarted
from admissible.delegated_gate.native_canary import create_canary_session
from admissible.delegated_gate.reducer import reduce
from admissible.delegated_gate.store import (
    AtomicDelegatedSessionStore,
    DurabilityError,
    StaleRevisionError,
)


def _raise(error: BaseException):
    def fail(*_args, **_kwargs):
        raise error

    return fail


def _fake_move(calls: list[int]):
    def move(source: Path, destination: Path, flags: int) -> None:
        calls.append(flags)
        if destination.exists() and not flags & MOVEFILE_REPLACE_EXISTING:
            raise WindowsMoveFileError(183, "already exists")
        os.replace(source, destination)

    return move


@pytest.mark.skipif(os.name != "nt", reason="real MoveFileExW is Windows-specific")
def test_default_windows_adapter_create_only_conflict_and_cas_replace(tmp_path: Path):
    adapter = PlatformDurabilityAdapter()
    path = tmp_path / "authority.json"
    initial = b'{"revision":0}\n'
    created = adapter.publish(path, initial, mode=PublicationMode.CREATE_ONLY)
    assert created.profile_id == WINDOWS_MOVEFILEEX_PROFILE
    assert created.file_content is FileContentDurability.FILE_CONTENT_DURABLE
    assert created.metadata is PublicationMetadataDurability.PUBLICATION_METADATA_DURABLE
    with pytest.raises(PublicationConflict):
        adapter.publish(path, b'{"revision":999}\n', mode=PublicationMode.CREATE_ONLY)
    assert path.read_bytes() == initial
    replacement = b'{"revision":1}\n'
    replaced = adapter.publish(
        path,
        replacement,
        mode=PublicationMode.REPLACE_EXISTING,
        replacement_authority=ReplacementAuthority.CAS_LOCK_HELD_AFTER_VALIDATION,
    )
    assert replaced.metadata is PublicationMetadataDurability.PUBLICATION_METADATA_DURABLE
    assert path.read_bytes() == replacement
    assert not tuple(tmp_path.glob(".*.tmp"))


def test_windows_flags_are_write_through_and_replace_is_authority_gated(tmp_path: Path):
    calls: list[int] = []
    adapter = PlatformDurabilityAdapter(
        platform_name="nt",
        windows_move=_fake_move(calls),
        directory_open=_raise(AssertionError("Windows must not open a directory for fsync")),
    )
    path = tmp_path / "record.json"
    adapter.publish(path, b"one", mode=PublicationMode.CREATE_ONLY)
    with pytest.raises(Exception, match="typed lock/CAS"):
        adapter.publish(path, b"two", mode=PublicationMode.REPLACE_EXISTING)
    adapter.publish(
        path,
        b"two",
        mode=PublicationMode.REPLACE_EXISTING,
        replacement_authority=ReplacementAuthority.CAS_LOCK_HELD_AFTER_VALIDATION,
    )
    assert calls == [MOVEFILE_WRITE_THROUGH, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING]
    assert path.read_bytes() == b"two"


def test_windows_api_unavailable_is_typed_and_cleans_temp(tmp_path: Path):
    def unavailable(_source: Path, destination: Path, _flags: int) -> None:
        raise PublicationApiUnavailable(
            "unavailable",
            path=destination,
            file_content_durable=True,
            metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNSUPPORTED,
        )

    adapter = PlatformDurabilityAdapter(platform_name="nt", windows_move=unavailable)
    with pytest.raises(PublicationApiUnavailable) as raised:
        adapter.publish(tmp_path / "record.json", b"data", mode=PublicationMode.CREATE_ONLY)
    assert raised.value.metadata_status is PublicationMetadataDurability.PUBLICATION_METADATA_UNSUPPORTED
    assert not tuple(tmp_path.iterdir())


def test_movefileex_failure_before_visibility_is_typed_and_cleans_temp(tmp_path: Path):
    adapter = PlatformDurabilityAdapter(
        platform_name="nt",
        windows_move=_raise(WindowsMoveFileError(5, "access denied")),
    )
    final = tmp_path / "record.json"
    with pytest.raises(PublicationFailureBeforeVisibility) as raised:
        adapter.publish(final, b"data", mode=PublicationMode.CREATE_ONLY)
    assert raised.value.to_diagnostic()["os_error_code"] == 5
    assert not final.exists()
    assert not tuple(tmp_path.iterdir())


def test_movefileex_failure_after_visibility_is_metadata_uncertain_and_inert(tmp_path: Path):
    def visible_then_fail(source: Path, destination: Path, _flags: int) -> None:
        os.replace(source, destination)
        raise WindowsMoveFileError(5, "post-move failure")

    adapter = PlatformDurabilityAdapter(platform_name="nt", windows_move=visible_then_fail)
    final = tmp_path / "record.json"
    with pytest.raises(PublicationVisibleButMetadataUncertain) as raised:
        adapter.publish(final, b"data", mode=PublicationMode.CREATE_ONLY)
    assert raised.value.publication_visible is True
    assert raised.value.metadata_status is PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN
    assert final.read_bytes() == b"data"
    assert tuple(tmp_path.iterdir()) == (final,)


@pytest.mark.parametrize(
    ("adapter_kwargs", "expected"),
    [
        ({"writer": _raise(OSError("write failed"))}, FileWriteFailure),
        ({"flusher": _raise(OSError("flush failed"))}, FileFlushFailure),
        ({"file_sync": _raise(OSError("fsync failed"))}, FileDurableFlushFailure),
    ],
)
def test_write_flush_and_file_fsync_failures_are_distinct_and_prepublication(
    tmp_path: Path, adapter_kwargs: dict, expected: type[Exception]
):
    adapter = PlatformDurabilityAdapter(platform_name="nt", **adapter_kwargs)
    with pytest.raises(expected):
        adapter.publish(tmp_path / "record.json", b"data", mode=PublicationMode.CREATE_ONLY)
    assert not tuple(tmp_path.iterdir())


def test_cleanup_failure_is_typed_without_claiming_publication(tmp_path: Path, monkeypatch):
    adapter = PlatformDurabilityAdapter(
        platform_name="nt", writer=_raise(OSError("write failed"))
    )
    monkeypatch.setattr(adapter, "_cleanup", lambda _path: OSError("cleanup failed"))
    with pytest.raises(TemporaryCleanupFailure) as raised:
        adapter.publish(tmp_path / "record.json", b"data", mode=PublicationMode.CREATE_ONLY)
    assert raised.value.publication_visible is False
    leftovers = tuple(tmp_path.iterdir())
    assert len(leftovers) == 1 and leftovers[0].name.endswith(".tmp")
    leftovers[0].unlink()


def test_post_publication_fingerprint_mismatch_is_typed(tmp_path: Path):
    def corrupt(source: Path, destination: Path, _flags: int) -> None:
        os.replace(source, destination)
        destination.write_bytes(b"corrupt")

    adapter = PlatformDurabilityAdapter(platform_name="nt", windows_move=corrupt)
    final = tmp_path / "record.json"
    with pytest.raises(PostPublicationFingerprintMismatch) as raised:
        adapter.publish(final, b"intended", mode=PublicationMode.CREATE_ONLY)
    assert raised.value.publication_visible is True
    assert final.read_bytes() == b"corrupt"


def test_post_publication_missing_final_is_typed_reload_failure(tmp_path: Path):
    def vanish(source: Path, destination: Path, _flags: int) -> None:
        os.replace(source, destination)
        destination.unlink()

    adapter = PlatformDurabilityAdapter(platform_name="nt", windows_move=vanish)
    with pytest.raises(PostPublicationReloadFailure):
        adapter.publish(tmp_path / "record.json", b"data", mode=PublicationMode.CREATE_ONLY)


def test_windows_same_volume_check_precedes_move(tmp_path: Path, monkeypatch):
    calls: list[int] = []
    adapter = PlatformDurabilityAdapter(platform_name="nt", windows_move=_fake_move(calls))
    monkeypatch.setattr(durability_module, "_same_volume", lambda _source, _destination: False)
    with pytest.raises(SameVolumeRequired):
        adapter.publish(tmp_path / "record.json", b"data", mode=PublicationMode.CREATE_ONLY)
    assert calls == [] and not tuple(tmp_path.iterdir())


def test_posix_directory_fsync_is_mandatory_after_create_and_replace(tmp_path: Path):
    calls: list[tuple[str, int | str]] = []
    adapter = PlatformDurabilityAdapter(
        platform_name="posix",
        directory_open=lambda path, _flags: calls.append(("open", os.fspath(path))) or 41,
        directory_sync=lambda fd: calls.append(("fsync", fd)),
        closer=lambda fd: calls.append(("close", fd)),
    )
    path = tmp_path / "record.json"
    adapter.publish(path, b"one", mode=PublicationMode.CREATE_ONLY)
    adapter.publish(
        path,
        b"two",
        mode=PublicationMode.REPLACE_EXISTING,
        replacement_authority=ReplacementAuthority.CAS_LOCK_HELD_AFTER_VALIDATION,
    )
    assert calls == [
        ("open", os.fspath(tmp_path)), ("fsync", 41), ("close", 41),
        ("open", os.fspath(tmp_path)), ("fsync", 41), ("close", 41),
    ]
    assert path.read_bytes() == b"two"


def test_posix_directory_open_or_fsync_failure_is_visible_uncertainty(tmp_path: Path):
    for name, adapter in (
        (
            "open",
            PlatformDurabilityAdapter(
                platform_name="posix", directory_open=_raise(OSError("open failed"))
            ),
        ),
        (
            "fsync",
            PlatformDurabilityAdapter(
                platform_name="posix",
                directory_open=lambda _path, _flags: 42,
                directory_sync=_raise(OSError("fsync failed")),
                closer=lambda _fd: None,
            ),
        ),
    ):
        final = tmp_path / f"{name}.json"
        with pytest.raises(PublicationVisibleButMetadataUncertain) as raised:
            adapter.publish(final, b"data", mode=PublicationMode.CREATE_ONLY)
        assert raised.value.publication_visible is True
        assert final.read_bytes() == b"data"


def test_posix_create_only_temp_unlink_failure_stays_visible_uncertainty_and_cleans(tmp_path: Path):
    adapter = PlatformDurabilityAdapter(
        platform_name="posix", unlinker=_raise(OSError("unlink failed"))
    )
    final = tmp_path / "record.json"
    with pytest.raises(PublicationVisibleButMetadataUncertain):
        adapter.publish(final, b"data", mode=PublicationMode.CREATE_ONLY)
    assert final.read_bytes() == b"data"
    assert tuple(tmp_path.iterdir()) == (final,)


def test_posix_atomic_publication_failure_is_previsibility(tmp_path: Path):
    adapter = PlatformDurabilityAdapter(
        platform_name="posix", posix_link=_raise(OSError("link failed"))
    )
    final = tmp_path / "record.json"
    with pytest.raises(PublicationFailureBeforeVisibility):
        adapter.publish(final, b"data", mode=PublicationMode.CREATE_ONLY)
    assert not final.exists() and not tuple(tmp_path.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="production Windows store path")
def test_delegated_store_windows_create_replace_cas_and_restart(tmp_path: Path):
    directory = tmp_path / "sessions"
    store = AtomicDelegatedSessionStore(directory)
    initial = create_canary_session(session_id="windows-store")
    store.create(initial)
    advanced = reduce(initial, GateExecutionStarted(initial.current_gate.gate_id))
    store.replace(advanced, expected_revision=0)
    with pytest.raises(StaleRevisionError):
        store.replace(advanced, expected_revision=0)
    restarted = AtomicDelegatedSessionStore(directory)
    assert restarted.load(initial.session_id) == advanced


def test_delegated_prepublication_failure_keeps_last_validated_revision(tmp_path: Path):
    calls: list[int] = []
    working = PlatformDurabilityAdapter(platform_name="nt", windows_move=_fake_move(calls))
    directory = tmp_path / "sessions"
    store = AtomicDelegatedSessionStore(directory, durability_adapter=working)
    initial = create_canary_session(session_id="last-durable")
    store.create(initial)
    advanced = reduce(initial, GateExecutionStarted(initial.current_gate.gate_id))
    store.durability_adapter = PlatformDurabilityAdapter(
        platform_name="nt", windows_move=_raise(WindowsMoveFileError(5, "denied"))
    )
    with pytest.raises(DurabilityError):
        store.replace(advanced, expected_revision=0)
    restarted = AtomicDelegatedSessionStore(directory, durability_adapter=working)
    assert restarted.load(initial.session_id) == initial


@pytest.mark.skipif(os.name != "nt", reason="real production capability path")
def test_production_capability_probe_is_external_complete_and_clean(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    future = tmp_path / "future-run"
    before = os.stat(source)
    result = probe_platform_durability(
        parent=tmp_path, source_root=source, future_run_root=future
    )
    after = os.stat(source)
    assert result.ready
    assert result.create_only_result is CapabilityStep.CONFLICT_PRESERVED
    assert result.replace_result is CapabilityStep.SUCCEEDED
    assert result.cleanup_result is CapabilityStep.SUCCEEDED
    assert not future.exists()
    assert (before.st_dev, before.st_ino, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_mtime_ns
    )
    assert not tuple(tmp_path.glob(".admissible-durability-probe-*"))


def test_capability_api_unavailable_blocks_and_cleans(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    future = tmp_path / "future-run"
    adapter = PlatformDurabilityAdapter(
        platform_name="nt",
        windows_move=_raise(
            PublicationApiUnavailable(
                "unavailable",
                path=future,
                metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNSUPPORTED,
            )
        ),
    )
    result = probe_platform_durability(
        parent=tmp_path, source_root=source, future_run_root=future, adapter=adapter
    )
    assert not result.ready
    assert result.create_only_result is CapabilityStep.FAILED
    assert result.cleanup_result is CapabilityStep.SUCCEEDED
    assert not future.exists() and not tuple(tmp_path.glob(".admissible-durability-probe-*"))


def test_durability_module_has_no_shell_or_subprocess_path():
    source = Path(durability_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert "subprocess" not in imported
