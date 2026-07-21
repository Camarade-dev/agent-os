"""Focused registration proof for the neon-siege-v1 comparison profile.

No live provider is reachable from this module. Positive control material is a
minimal deterministic implementation used only to prove the embedded verifier
and local-start cleanup; it is not the governed task solution.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

from test_admissible_delegated_gate_native_executor import (
    _command,
    _commit,
    _injected_test_cursor,
)

from admissible.delegated_gate import native_canary as nc
from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.fixture_registry import (
    NEON_SIEGE_FIXTURE_ID,
    NEON_SIEGE_FIXTURE_VERSION,
    NEON_SIEGE_INITIAL_COMMIT_MESSAGE,
    build_neon_siege_blank_repository,
    fixture_material_tree_hash,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION,
    NEON_SIEGE_PROFILE,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    AUTHORIZATION_SCHEMA_VERSION_V4,
    OWNER_AUTHORIZATION_DIGEST_ENV,
    _authorized,
    _observe_built_fixture,
    build_canary_repository,
    build_native_agent_prompt,
    build_profile_authorization_payload,
    create_canary_session,
    main,
    observe_initialized_workspace_identity,
    resolve_fixture_builder,
    resolve_registered_profile,
    registered_profiles,
)
from admissible.delegated_gate.neon_siege_mission import (
    NEON_SIEGE_COMPLETION_CONDITIONS_TEXT,
    NEON_SIEGE_EXACT_USER_PROMPT,
    NEON_SIEGE_EXACT_USER_PROMPT_BYTE_LENGTH,
    NEON_SIEGE_EXACT_USER_PROMPT_SHA256,
    NEON_SIEGE_REQUIRED_COMMIT_MESSAGE,
    NEON_SIEGE_REQUIRED_MATERIAL_PATHS,
    NEON_SIEGE_VERIFIER_SOURCE,
    NEON_SIEGE_VERIFIER_SOURCE_SHA256,
)


PROFILE = NEON_SIEGE_PROFILE
EXPECTED_PROFILE_FINGERPRINT = "da7a93272544a05b60887973a80c72e2541104053162646c5daa5a30920a5b35"
EXPECTED_FIXTURE_HEAD = "46f664726411baee7d0416607b50a53044727d0d"
EXPECTED_FIXTURE_TREE = "0d93249c0995a607b9daf0b2916728e2ed46ab99716939665b956aac9cbdecf4"
OWNER_PHRASE = "AUTHORIZE NATIVE CURSOR NEON SIEGE 001"

LEGACY_FINGERPRINTS = {
    "act-2a-high-score-canary-v1": "4e4f4672a5181ee178dc20d7a7c04865a2789f9430793dd882048cc802f78d57",
    "incident-replay-v1": "ceac9c5dc344d7f5b5d24c530cd28a29012c3dcbb0f4fa7906884caec6845bc3",
    "workflow-recovery-v1": "ed67459c803bf439ee3325cdf9fa069d48677408412ff283ab86a4234d9ae2f8",
    "workflow-recovery-v2": "e4bdcf5a2f5ae1cae6435bc8881eff40e6154762e9cbd76c6054bd0e61e78724",
}


def _source_head(source: Path) -> str:
    return _command(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip().lower()


def _profile_variant(**changes) -> NativeMissionProfile:
    data = dict(PROFILE.to_dict())
    data.update(changes)
    if "verifier_source" in changes:
        data["verifier_source_sha256"] = hashlib.sha256(
            changes["verifier_source"].encode("utf-8")
        ).hexdigest()
    body = {key: value for key, value in data.items() if key != "profile_fingerprint"}
    data["profile_fingerprint"] = fingerprint(body)
    return NativeMissionProfile.from_dict(data)


def _owner_digest(phrase: str, payload) -> str:
    return hashlib.sha256(
        phrase.encode("utf-8") + b"\0" + canonical_bytes(payload.to_dict())
    ).hexdigest()


def _run_verifier(workspace: Path, script_path: Path) -> subprocess.CompletedProcess[str]:
    script_path.write_text(PROFILE.verifier_source, encoding="utf-8", newline="\n")
    return subprocess.run(
        ["node", "--preserve-symlinks", "--preserve-symlinks-main", str(script_path), str(workspace)],
        cwd=script_path.parent,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=PROFILE.verifier_timeout_seconds,
    )


def _write_positive_control(repository: Path) -> None:
    """Minimal deterministic implementation that satisfies the embedded verifier."""

    (repository / "README.md").write_text(
        "# Neon Siege\n\nPositive-control scaffold for verifier tests.\n\n"
        "Run `npm test` and `npm start`. Deploy by publishing the static files.\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "package.json").write_text(
        json.dumps(
            {
                "name": "neon-siege-positive-control",
                "version": "1.0.0",
                "private": True,
                "type": "module",
                "scripts": {
                    "test": "node --preserve-symlinks --preserve-symlinks-main --test",
                    "start": "node server.js",
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "index.html").write_text(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Neon Siege</title>"
        "<link rel=\"stylesheet\" href=\"style.css\"></head>"
        "<body><h1>Neon Siege</h1><canvas id=\"game\"></canvas>"
        "<script type=\"module\" src=\"main.js\"></script></body></html>\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "style.css").write_text(
        "body{margin:0;background:#050510;color:#9ff;font-family:sans-serif}"
        "canvas{display:block;width:100%;max-width:960px;margin:0 auto}\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "game-state.js").write_text(
        """const ENEMY_TYPES = [
  { id: 'chaser', behavior: 'seek' },
  { id: 'tank', behavior: 'brute' },
  { id: 'dasher', behavior: 'strafe' },
];
const HIGH_SCORE_KEY = 'neon-siege-high-score';
const UPGRADE_CHOICES = [
  { id: 'fire-rate', name: 'Fire Rate' },
  { id: 'max-health', name: 'Max Health' },
  { id: 'dash-cooldown', name: 'Dash Cooldown' },
];

export function createGameState({ storage } = {}) {
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') {
    throw new TypeError('injectable storage is required');
  }
  let phase = 'title';
  let health = 100;
  let score = 0;
  let wave = 1;
  let dashCooldown = 0;
  let highScore = Number(storage.getItem(HIGH_SCORE_KEY) || 0);
  const upgradeLevels = { 'fire-rate': 0, 'max-health': 0, 'dash-cooldown': 0 };
  // localStorage / AudioContext / mute vocabulary for static coverage proof.
  const audio = { mute: false, AudioContext: true, localStorage: true };

  const api = {
    start() { phase = 'playing'; return api.getState(); },
    pause() { phase = 'paused'; return api.getState(); },
    resume() { phase = 'playing'; return api.getState(); },
    restart() {
      phase = 'title';
      health = 100;
      score = 0;
      wave = 1;
      dashCooldown = 0;
      return api.getState();
    },
    applyDamage(amount) { health = Math.max(0, health - (Number(amount) || 0)); return api.getState(); },
    activateDash() { dashCooldown = 30; return api.getState(); },
    offerUpgrades() { return UPGRADE_CHOICES.map((entry) => ({ ...entry })); },
    applyUpgrade(id) {
      if (!(id in upgradeLevels)) throw new Error(`unknown upgrade: ${id}`);
      upgradeLevels[id] += 1;
      return api.getState();
    },
    advanceWave() { wave += 1; return api.getState(); },
    addScore(points) {
      score += Number(points) || 0;
      if (score > highScore) {
        highScore = score;
        storage.setItem(HIGH_SCORE_KEY, String(highScore));
      }
      return api.getState();
    },
    triggerGameOver() {
      phase = 'gameover';
      if (score > highScore) {
        highScore = score;
        storage.setItem(HIGH_SCORE_KEY, String(highScore));
      }
      return api.getState();
    },
    listEnemyTypes() { return ENEMY_TYPES.map((entry) => ({ ...entry })); },
    getState() {
      return {
        phase, health, score, wave, dashCooldown, highScore,
        upgradeLevels: { ...upgradeLevels }, audio,
      };
    },
  };
  return api;
}
""",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "main.js").write_text(
        "import { createGameState } from './game-state.js';\n"
        "if (globalThis.localStorage) {\n"
        "  createGameState({ storage: globalThis.localStorage });\n"
        "}\n"
        "console.log('Neon Siege boot');\n",
        encoding="utf-8",
        newline="\n",
    )
    (repository / "server.js").write_text(
        """import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const host = process.env.HOST || '127.0.0.1';
const port = Number(process.env.PORT || 8765);
const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

const server = http.createServer(async (req, res) => {
  const path = (req.url || '/').split('?')[0];
  const relative = path === '/' ? 'index.html' : path.replace(/^\\/+/, '');
  try {
    const data = await readFile(join(root, relative));
    res.writeHead(200, { 'Content-Type': types[extname(relative)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404).end('missing');
  }
});
server.listen(port, host, () => {
  console.log(`listening on http://${host}:${port}/`);
});
""",
        encoding="utf-8",
        newline="\n",
    )
    test_dir = repository / "test"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir()
    (test_dir / "game-state.test.js").write_text(
        """import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createGameState } from '../game-state.js';

function memory() {
  const values = new Map();
  return {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(String(key), String(value)); },
  };
}

describe('neon siege core state', () => {
  it('covers wave, upgrade, restart, dash, score, and health transitions', () => {
    const game = createGameState({ storage: memory() });
    game.start();
    game.pause();
    game.resume();
    const before = game.getState().health;
    game.applyDamage(10);
    assert.equal(game.getState().health, before - 10);
    game.activateDash();
    assert.ok(game.getState().dashCooldown > 0);
    const choices = game.offerUpgrades();
    assert.equal(choices.length, 3);
    game.applyUpgrade(choices[0].id);
    game.applyUpgrade(choices[0].id);
    assert.equal(game.getState().upgradeLevels[choices[0].id], 2);
    const wave = game.getState().wave;
    game.advanceWave();
    assert.equal(game.getState().wave, wave + 1);
    game.addScore(40);
    assert.equal(game.getState().score, 40);
    game.triggerGameOver();
    assert.match(game.getState().phase, /over/i);
    game.restart();
    assert.equal(game.getState().score, 0);
    assert.equal(game.listEnemyTypes().length, 3);
  });
});
""",
        encoding="utf-8",
        newline="\n",
    )
    _commit(repository, PROFILE.required_commit_message)


@pytest.fixture(scope="module")
def built_fixture(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    root = tmp_path_factory.mktemp("neon-siege-fixture")
    first = build_neon_siege_blank_repository(root, repository_name="first")
    npm = _command(["npm.cmd", "test"], cwd=first.repository)
    second_root = root / "rebuild"
    second_root.mkdir()
    second = build_neon_siege_blank_repository(second_root, repository_name="second")
    return SimpleNamespace(root=root, first=first, second=second, npm=npm)


def test_exact_prompt_bytes_are_frozen():
    encoded = NEON_SIEGE_EXACT_USER_PROMPT.encode("utf-8")
    assert len(encoded) == NEON_SIEGE_EXACT_USER_PROMPT_BYTE_LENGTH == 2739
    assert hashlib.sha256(encoded).hexdigest() == NEON_SIEGE_EXACT_USER_PROMPT_SHA256 == (
        "5a4ad58e5aef0309bcd347b209682c5273738fabcfed959e6b19c6b3a3aefd30"
    )
    assert PROFILE.mission_text == NEON_SIEGE_EXACT_USER_PROMPT


def test_profile_exact_identity_budgets_and_canonical_round_trip():
    assert PROFILE.schema_version == MISSION_PROFILE_SCHEMA_VERSION
    assert PROFILE.profile_id == "neon-siege-v1"
    assert (PROFILE.fixture_id, PROFILE.fixture_version) == (NEON_SIEGE_FIXTURE_ID, NEON_SIEGE_FIXTURE_VERSION)
    assert PROFILE.run_id == PROFILE.session_id == "native-cursor-neon-siege-001"
    assert PROFILE.mission_id == "native-neon-siege"
    assert PROFILE.gate_id == "neon-siege-gate"
    assert PROFILE.model == "auto"
    assert PROFILE.timeout_seconds == 3600
    assert (PROFILE.stdout_byte_limit, PROFILE.stderr_byte_limit) == (8_388_608, 1_048_576)
    assert PROFILE.fixture_initial_commit_message == NEON_SIEGE_INITIAL_COMMIT_MESSAGE
    assert PROFILE.required_commit_message == NEON_SIEGE_REQUIRED_COMMIT_MESSAGE
    assert PROFILE.budgets == (1, 1, 0, 0, 0)
    assert PROFILE.required_evidence_kinds == ("target_tree", "git_state", "verification_command")
    assert PROFILE.required_material_paths == NEON_SIEGE_REQUIRED_MATERIAL_PATHS
    assert PROFILE.completion_conditions_text == NEON_SIEGE_COMPLETION_CONDITIONS_TEXT
    assert PROFILE.verifier_source == NEON_SIEGE_VERIFIER_SOURCE
    assert PROFILE.verifier_source_sha256 == NEON_SIEGE_VERIFIER_SOURCE_SHA256
    assert (PROFILE.verifier_timeout_seconds, PROFILE.verifier_output_limit_bytes) == (60, 262144)
    (checkpoint,) = PROFILE.checkpoint_commands
    assert (checkpoint.command_id, checkpoint.argv) == ("npm-test", ("npm.cmd", "test"))
    assert (checkpoint.timeout_seconds, checkpoint.max_capture_bytes) == (300, 1_048_576)
    assert PROFILE.profile_fingerprint == EXPECTED_PROFILE_FINGERPRINT
    assert fingerprint(PROFILE._body()) == PROFILE.profile_fingerprint
    assert NativeMissionProfile.from_dict(json.loads(json.dumps(PROFILE.to_dict()))) == PROFILE
    assert [clause[0] for clause in PROFILE.gate_clauses] == [
        "neon-siege.material",
        "neon-siege.tests",
        "neon-siege.behavior",
        "neon-siege.git",
    ]


def test_registration_preserves_existing_fingerprints_and_adds_neon_siege():
    profiles = registered_profiles()
    for profile_id, digest in LEGACY_FINGERPRINTS.items():
        assert profiles[profile_id].profile_fingerprint == digest
    assert profiles["neon-siege-v1"] == PROFILE
    assert resolve_registered_profile("neon-siege-v1") == PROFILE
    assert resolve_fixture_builder(NEON_SIEGE_FIXTURE_ID, NEON_SIEGE_FIXTURE_VERSION) is build_neon_siege_blank_repository
    with pytest.raises(ValueError, match="unknown mission profile"):
        resolve_registered_profile("neon-siege-v2")
    with pytest.raises(ValueError, match="unknown fixture builder"):
        resolve_fixture_builder(NEON_SIEGE_FIXTURE_ID, 2)


def test_fixture_is_blank_clean_offline_and_deterministic(built_fixture):
    first, second = built_fixture.first, built_fixture.second
    assert built_fixture.npm.returncode == 0
    assert first.initial_commit_message == NEON_SIEGE_INITIAL_COMMIT_MESSAGE
    assert first.initial_head == EXPECTED_FIXTURE_HEAD
    assert first.initial_material_tree_hash == EXPECTED_FIXTURE_TREE
    assert first.initial_material_tree_hash == fixture_material_tree_hash(first.repository)
    assert (second.initial_head, second.initial_material_tree_hash, second.initial_commit_message) == (
        first.initial_head,
        first.initial_material_tree_hash,
        first.initial_commit_message,
    )
    assert _command(["git", "remote"], cwd=first.repository).stdout.strip() == ""
    assert _command(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=first.repository).stdout == ""
    assert _command(["git", "rev-list", "--count", "HEAD"], cwd=first.repository).stdout.strip() == "1"
    material = {
        path.relative_to(first.repository).as_posix()
        for path in first.repository.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(first.repository).parts
    }
    assert material == {".gitignore", "README.md", "package.json", "test/fixture-identity.test.js"}
    combined = "\n".join((first.repository / rel).read_text(encoding="utf-8") for rel in sorted(material))
    for forbidden in ("createGameState", "AudioContext", "dashCooldown", "offerUpgrades", "listEnemyTypes"):
        assert forbidden not in combined


def test_real_embedded_verifier_rejects_the_untouched_fixture(built_fixture):
    completed = _run_verifier(built_fixture.first.repository, built_fixture.root / "negative-verifier.mjs")
    assert completed.returncode != 0
    assert "index.html" in (completed.stderr + completed.stdout).replace("\\", "/")


def test_positive_control_passes_verifier_and_cleans_local_server(tmp_path: Path):
    fixture = build_neon_siege_blank_repository(tmp_path, repository_name="work")
    _write_positive_control(fixture.repository)
    npm_test = _command(["npm.cmd", "test"], cwd=fixture.repository)
    assert npm_test.returncode == 0
    completed = _run_verifier(fixture.repository, tmp_path / "positive-verifier.mjs")
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "neon-siege behavioral verifier passed" in completed.stdout
    assert "subjective visual polish was not independently established" in completed.stdout
    try:
        with socket.create_connection(("127.0.0.1", 8765), timeout=0.2):
            pytest.fail("local start probe left port 8765 open")
    except OSError:
        pass


def test_rendered_prompt_preserves_exact_mission_and_git_contract(tmp_path: Path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    state = create_canary_session(session_id=PROFILE.session_id, profile=PROFILE)
    prompt = build_native_agent_prompt(
        mission=state.mission,
        gate_contract=state.current_gate,
        work_workspace=workspace,
        required_commit_message=PROFILE.required_commit_message,
        completion_conditions=PROFILE.completion_conditions_text,
        profile=PROFILE,
    )
    mission_block = prompt.split("Immutable mission:\n", 1)[1].split("\n\nCurrent gate objective:", 1)[0]
    assert mission_block == NEON_SIEGE_EXACT_USER_PROMPT
    assert "git log -1 --format=%B" in prompt
    assert NEON_SIEGE_REQUIRED_COMMIT_MESSAGE in prompt
    for path in NEON_SIEGE_REQUIRED_MATERIAL_PATHS:
        assert path in prompt
    assert "createGameState" in prompt
    assert PROFILE.verifier_source not in prompt


def _payload_harness(tmp_path: Path) -> SimpleNamespace:
    source_parent = tmp_path / "source-parent"
    source_parent.mkdir()
    source = build_canary_repository(source_parent, repository_name="source").repository
    fixture_parent = tmp_path / "fixture-parent"
    fixture_parent.mkdir()
    fixture = build_neon_siege_blank_repository(fixture_parent, repository_name="work")
    config, attestor = _injected_test_cursor(tmp_path)
    attestation = attestor(config)
    identity = _observe_built_fixture(fixture, PROFILE)
    run_root = tmp_path / PROFILE.run_id
    payload = build_profile_authorization_payload(
        source_repository=source,
        source_head=_source_head(source),
        attestation=attestation,
        run_root=run_root,
        profile=PROFILE,
        initialized_workspace=identity,
    )
    return SimpleNamespace(
        source=source,
        fixture=fixture,
        config=config,
        attestation=attestation,
        identity=identity,
        run_root=run_root,
        payload=payload,
    )


def test_v4_payload_and_owner_authorization_mismatch_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    harness = _payload_harness(tmp_path)
    payload = harness.payload
    assert payload.schema_version == AUTHORIZATION_SCHEMA_VERSION_V4
    assert payload.mission_profile == PROFILE
    assert payload.initialized_workspace.initial_git_head == EXPECTED_FIXTURE_HEAD
    assert payload.initialized_workspace.initial_material_tree_hash == EXPECTED_FIXTURE_TREE
    digest = _owner_digest(OWNER_PHRASE, payload)
    monkeypatch.setenv(OWNER_AUTHORIZATION_DIGEST_ENV, digest)
    assert _authorized(OWNER_PHRASE, payload, active_source_repository=harness.source)
    assert not _authorized("WRONG PHRASE", payload, active_source_repository=harness.source)
    monkeypatch.setenv(OWNER_AUTHORIZATION_DIGEST_ENV, "0" * 64)
    assert not _authorized(OWNER_PHRASE, payload, active_source_repository=harness.source)
    substituted = _profile_variant(mission_text=PROFILE.mission_text + "\nEXTRA.")
    substituted_payload = build_profile_authorization_payload(
        source_repository=harness.source,
        source_head=_source_head(harness.source),
        attestation=harness.attestation,
        run_root=harness.run_root,
        profile=substituted,
        initialized_workspace=harness.identity,
    )
    monkeypatch.setenv(OWNER_AUTHORIZATION_DIGEST_ENV, digest)
    assert not _authorized(OWNER_PHRASE, substituted_payload, active_source_repository=harness.source)


def test_preflight_payload_identity_target_absence_and_cli_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    harness = _payload_harness(tmp_path)
    target = Path(r"C:\Users\stris\Documents\Projets\ENTRE\native-cursor-neon-siege-001")
    alternate = Path(r"C:\Users\stris\Documents\Projets\ENTRE\agent-os\native-cursor-neon-siege-001")
    assert not target.exists()
    assert not alternate.exists()

    first = observe_initialized_workspace_identity(PROFILE)
    second = observe_initialized_workspace_identity(PROFILE)
    assert first == second
    assert first.initial_git_head == EXPECTED_FIXTURE_HEAD
    assert first.initial_material_tree_hash == EXPECTED_FIXTURE_TREE

    payload_a = build_profile_authorization_payload(
        source_repository=harness.source,
        source_head=_source_head(harness.source),
        attestation=harness.attestation,
        run_root=tmp_path / PROFILE.run_id,
        profile=PROFILE,
        initialized_workspace=first,
    )
    payload_b = build_profile_authorization_payload(
        source_repository=harness.source,
        source_head=_source_head(harness.source),
        attestation=harness.attestation,
        run_root=tmp_path / PROFILE.run_id,
        profile=PROFILE,
        initialized_workspace=second,
    )
    assert canonical_bytes(payload_a.to_dict()) == canonical_bytes(payload_b.to_dict())
    assert payload_a.schema_version == AUTHORIZATION_SCHEMA_VERSION_V4
    assert not (tmp_path / PROFILE.run_id).exists()
    assert not target.exists()

    cli = [
        "--source-repository", "unused-source",
        "--required-source-head", "0" * 40,
        "--run-root", "unused-root",
        "--run-id", PROFILE.run_id,
        "--session-id", PROFILE.session_id,
        "--executable", "cursor-agent",
        "--attestation-class", "wrapper-chain",
        "--profile-id", PROFILE.profile_id,
        "--preflight-only",
    ]
    assert main([*cli, "--timeout-seconds", "900"]) == 2
    blocked = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert blocked["status"] == "PREFLIGHT_BLOCKED"
    assert "timeout-seconds contradicts the selected profile" in blocked["detail"]
    assert blocked.get("provider_invocations", 0) == 0
    assert not target.exists()


def test_git_eligibility_contract_is_one_exact_commit_message():
    assert PROFILE.required_commit_message == "feat: build deployable Neon Siege browser game"
    assert "no commit-message body" in PROFILE.completion_conditions_text
    assert "use no `--trailer`" in PROFILE.completion_conditions_text
    assert "git log -1 --format=%B" in PROFILE.completion_conditions_text
    assert "zero remotes" in PROFILE.gate_clauses[-1][1] or "zero remotes" in PROFILE.completion_conditions_text
