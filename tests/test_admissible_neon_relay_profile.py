"""Focused registration and frozen-verifier proof for the neon-relay-v1 profile.

No provider is reachable from this module: nothing here spawns cursor-agent,
opens a socket, launches a browser, starts a server, installs a dependency or
creates a run root.  The only subprocesses are ``git`` read-only observations of
the immutable external fixture and ``node`` executions of the owner-frozen
behavioral verifier.

The synthetic conformance implementation below exists only to prove that the
frozen verifier contract is satisfiable.  It is test-only material, is written
exclusively under ``tmp_path`` outside every repository worktree, and is
deliberately not the governed task solution: it is never added to the game
fixture or to the production package.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
from unittest import mock

import pytest

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    MISSION_PROFILE_SCHEMA_VERSION_V3,
    MISSION_PROFILE_SCHEMA_VERSION_V4,
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NEON_RELAY_FIXTURE_REPOSITORY_PATH,
    NEON_RELAY_PROFILE,
    NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES,
    NEON_RELAY_VERIFIER_TIMEOUT_SECONDS,
    NEON_SIEGE_PROFILE,
    ONE_SHOT_PROFILE_BUDGETS,
    ClaimAuthority,
    ClaimAuthorship,
    ClaimObligationLevel,
    ClaimSetCoverageStatus,
    ClaimVerificationPlanAuthority,
    NativeMissionProfile,
    ResultClaim,
    VerificationAcceptancePredicate,
    VerificationEvidenceBinding,
    VerificationEvidenceBindingAuthority,
    VerificationEvidenceBindingAuthorship,
    VerificationEvidenceBindingCoverageStatus,
    VerificationEvidenceSourceAuthorityType,
    VerificationIndependenceRequirements,
    VerificationMode,
    VerificationNegativeControl,
    VerificationObligation,
    VerificationPlanAuthorship,
    VerificationPlanCoverageStatus,
    VerificationStrategy,
    WorkspaceSourceKind,
    create_native_mission_profile,
    load_native_mission_profile_document,
)
from admissible.delegated_gate.native_canary import (
    _initialized_identity_from_local_source,
    _observe_local_repository_source,
    build_native_agent_prompt,
    create_canary_session,
    registered_profiles,
    resolve_registered_profile,
)
from admissible.delegated_gate.neon_relay_mission import (
    NEON_RELAY_COMPLETION_CONDITIONS_SHA256,
    NEON_RELAY_COMPLETION_CONDITIONS_TEXT,
    NEON_RELAY_DOMAIN_MODULE_PATHS,
    NEON_RELAY_ENEMY_TYPES,
    NEON_RELAY_FIXTURE_MARKER,
    NEON_RELAY_MISSION_TEXT,
    NEON_RELAY_MISSION_TEXT_SHA256,
    NEON_RELAY_OPERATIONS,
    NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
    NEON_RELAY_REQUIRED_MATERIAL_PATHS,
    NEON_RELAY_STATES,
    NEON_RELAY_VERIFIER_CLAUSE_IDS,
    NEON_RELAY_VERIFIER_NON_CLAIMS,
    NEON_RELAY_VERIFIER_SOURCE,
    NEON_RELAY_VERIFIER_SOURCE_SHA256,
    NEON_RELAY_VERIFIER_SUCCESS_LINE,
)


PROFILE = NEON_RELAY_PROFILE

# ---------------------------------------------------------------------------
# Pinned identities. Every value below is computed from committed source or
# from the immutable external fixture; none may drift silently.
# ---------------------------------------------------------------------------

EXPECTED_SCHEMA_VERSION = "admissible_native_mission_profile_v2"
EXPECTED_PROFILE_ID = "neon-relay-v1"
EXPECTED_MISSION_ID = "native-neon-relay"
EXPECTED_GATE_ID = "neon-relay-gate"
EXPECTED_RUN_ID = "native-cursor-neon-relay-001"
EXPECTED_SESSION_ID = "native-cursor-neon-relay-001"
EXPECTED_MODEL = "auto"
EXPECTED_TIMEOUT_SECONDS = 2700
EXPECTED_STDOUT_BYTE_LIMIT = 8 * 1024 * 1024
EXPECTED_STDERR_BYTE_LIMIT = 1 * 1024 * 1024

EXPECTED_FIXTURE_PATH = r"C:\Users\stris\Documents\Projets\ENTRE\admissible-neon-relay-source"
EXPECTED_FIXTURE_HEAD = "85d25c26d1c44f714b4cb6c83c22fac1c0505373"
EXPECTED_FIXTURE_GIT_TREE = "793ead39dcfaa2139cd054c734c40fbd9117160f"
EXPECTED_FIXTURE_MATERIAL_TREE_HASH = (
    "2acd321870f136b1c9531071f57bbb72d71dbb99bd987039c375ba4598fd8e7f"
)
EXPECTED_FIXTURE_COMMIT_MESSAGE = "chore: initialize neon relay blank fixture"
EXPECTED_FIXTURE_TRACKED_PATHS = (".gitignore", "LOCAL_DEV.md", "package.json")

EXPECTED_MISSION_TEXT_SHA256 = (
    "30f35aa49847a394e3bf7c6ddf6d5d1dfa4565ae0fda1459e030c9a583dd02a8"
)
EXPECTED_COMPLETION_CONDITIONS_SHA256 = (
    "d8095523c5fb8ac3e8b43db80705a93791fe4717ca40b61634faabafea009320"
)
EXPECTED_VERIFIER_SOURCE_SHA256 = (
    "0e2afbd206933ad621b22e80755725d6436ea1f65319c914738254b0cfe001c5"
)
EXPECTED_PROFILE_FINGERPRINT = (
    "8ef57625f3fb369ff87d2981ff15753fcd45f0328c74bcb05ed81c8a61c9999d"
)
EXPECTED_PROFILE_DOCUMENT_SHA256 = (
    "27f4d6e0c81937c1a3e76da7c9c067738f879bc3f5a2a874ab48274e9f227e14"
)

# Every registered identity that existed before neon-relay-v1 was added.
LEGACY_FINGERPRINTS = {
    "act-2a-high-score-canary-v1": "4e4f4672a5181ee178dc20d7a7c04865a2789f9430793dd882048cc802f78d57",
    "incident-replay-v1": "ceac9c5dc344d7f5b5d24c530cd28a29012c3dcbb0f4fa7906884caec6845bc3",
    "workflow-recovery-v1": "ed67459c803bf439ee3325cdf9fa069d48677408412ff283ab86a4234d9ae2f8",
    "workflow-recovery-v2": "e4bdcf5a2f5ae1cae6435bc8881eff40e6154762e9cbd76c6054bd0e61e78724",
    "neon-siege-v1": "da7a93272544a05b60887973a80c72e2541104053162646c5daa5a30920a5b35",
}
EXPECTED_NEON_SIEGE_FINGERPRINT = LEGACY_FINGERPRINTS["neon-siege-v1"]


# ---------------------------------------------------------------------------
# Test-only synthetic conformance implementation.
# ---------------------------------------------------------------------------

_CONFORMANCE_PACKAGE_JSON = """{
  "name": "neon-relay",
  "private": true,
  "scripts": {
    "test": "node --test test/"
  },
  "type": "module",
  "version": "0.1.0"
}
"""

_CONFORMANCE_LOCAL_DEV_MD = """# Local development

## Running the tests

Run `npm test` from the project root. It uses the Node built-in test runner and
terminates on its own.

## Opening the game

Open `index.html` with the browser's own local open-file action, for example the
File menu's Open File entry, or by dragging the file onto a browser tab. No
build step and no other tooling are involved.
"""

_CONFORMANCE_INDEX_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Neon Relay</title>
    <link rel="stylesheet" href="style.css" />
  </head>
  <body>
    <main class="shell">
      <h1 class="title">Neon Relay</h1>
      <canvas id="arena" width="1280" height="720" aria-label="Neon Relay arena"></canvas>
      <section id="hud" class="hud">
        <span id="hud-health">Integrity</span>
        <span id="hud-dash">Dash</span>
        <span id="hud-relay">Relay</span>
        <span id="hud-sector">Sector</span>
      </section>
      <section id="overlay-title" class="overlay">Press Enter to begin</section>
      <section id="overlay-pause" class="overlay hidden">Paused</section>
      <section id="overlay-upgrade" class="overlay hidden">Choose an upgrade</section>
      <section id="overlay-over" class="overlay hidden">Relay lost</section>
      <section id="overlay-victory" class="overlay hidden">Relay secured</section>
    </main>
    <script type="module" src="src/main.js"></script>
  </body>
</html>
"""

_CONFORMANCE_STYLE_CSS = """:root {
  --neon-cyan: #4ff8ff;
  --neon-magenta: #ff4fd8;
  --neon-amber: #ffd04f;
  --void: #05060f;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: radial-gradient(circle at 50% 20%, #101433, var(--void) 70%);
  color: var(--neon-cyan);
  font-family: "Segoe UI", system-ui, sans-serif;
}

.shell {
  display: grid;
  gap: 0.75rem;
  padding: 1rem;
  max-width: 1920px;
  margin: 0 auto;
}

.title {
  margin: 0;
  letter-spacing: 0.4rem;
  text-transform: uppercase;
  text-shadow: 0 0 12px var(--neon-magenta);
}

canvas {
  width: 100%;
  max-width: 1920px;
  aspect-ratio: 16 / 9;
  background: #070a18;
  border: 1px solid var(--neon-cyan);
  box-shadow: 0 0 24px rgba(79, 248, 255, 0.35) inset;
}

.hud {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  font-variant-numeric: tabular-nums;
}

.overlay {
  padding: 0.75rem 1rem;
  border: 1px dashed var(--neon-amber);
  color: var(--neon-amber);
  text-align: center;
}

.overlay.hidden {
  display: none;
}

@media (max-width: 1400px) {
  .shell {
    padding: 0.5rem;
  }

  .title {
    font-size: 1.4rem;
  }
}
"""

_CONFORMANCE_SRC_RANDOM_JS = """// Explicit seeded random source. The domain never uses ambient randomness.
const MODULUS = 2147483647;
const MULTIPLIER = 16807;

export function createRandom(seed) {
  const normalized = Number(seed);
  const base = Number.isFinite(normalized) ? Math.floor(Math.abs(normalized)) : 1;
  let state = (base % (MODULUS - 1)) + 1;
  return {
    next() {
      state = (state * MULTIPLIER) % MODULUS;
      return (state - 1) / (MODULUS - 1);
    },
  };
}
"""

_CONFORMANCE_SRC_STATE_MACHINE_JS = """export const STATES = Object.freeze({
  TITLE: 'TITLE',
  RUNNING: 'RUNNING',
  PAUSED: 'PAUSED',
  UPGRADE: 'UPGRADE',
  GAME_OVER: 'GAME_OVER',
  VICTORY: 'VICTORY',
});

const TRANSITIONS = Object.freeze([
  Object.freeze(['TITLE', 'RUNNING']),
  Object.freeze(['RUNNING', 'PAUSED']),
  Object.freeze(['PAUSED', 'RUNNING']),
  Object.freeze(['RUNNING', 'UPGRADE']),
  Object.freeze(['UPGRADE', 'RUNNING']),
  Object.freeze(['RUNNING', 'GAME_OVER']),
  Object.freeze(['RUNNING', 'VICTORY']),
  Object.freeze(['GAME_OVER', 'TITLE']),
  Object.freeze(['VICTORY', 'TITLE']),
]);

export function legalTransitions() {
  return TRANSITIONS.map((pair) => [pair[0], pair[1]]);
}

export function canTransition(from, to) {
  return TRANSITIONS.some((pair) => pair[0] === from && pair[1] === to);
}
"""

_CONFORMANCE_SRC_ENTITIES_JS = """export const ARENA = Object.freeze({ width: 1280, height: 720 });

export const RELAY_ZONES = Object.freeze([
  Object.freeze({ x: 320, y: 200, radius: 140 }),
  Object.freeze({ x: 960, y: 240, radius: 140 }),
  Object.freeze({ x: 640, y: 560, radius: 140 }),
]);

export const ENEMY_ARCHETYPES = Object.freeze({
  chaser: Object.freeze({ id: 'chaser', health: 3, speed: 96, contact: 2 }),
  shooter: Object.freeze({ id: 'shooter', health: 2, speed: 54, contact: 1 }),
  splitter: Object.freeze({ id: 'splitter', health: 4, speed: 72, contact: 3 }),
});

export function listArchetypes() {
  return Object.keys(ENEMY_ARCHETYPES);
}

export function isArchetype(type) {
  return Object.prototype.hasOwnProperty.call(ENEMY_ARCHETYPES, type);
}

export function createPlayer() {
  return {
    health: 5,
    maxHealth: 5,
    x: ARENA.width / 2,
    y: ARENA.height / 2,
    dashCooldownMs: 0,
    dashCooldownTotalMs: 1200,
  };
}

export function createRelays(fullCharge) {
  return RELAY_ZONES.map((zone, index) => ({
    index,
    charge: 0,
    fullCharge,
    complete: false,
    zone,
  }));
}

export function createEnemy({ id, type, generation, x, y, relayIndex }) {
  const archetype = ENEMY_ARCHETYPES[type];
  if (!archetype) return null;
  const health = generation > 0 ? Math.max(1, Math.round(archetype.health / 2)) : archetype.health;
  return {
    id,
    type,
    generation,
    health,
    maxHealth: health,
    speed: archetype.speed,
    contact: archetype.contact,
    x,
    y,
    relayIndex,
  };
}
"""

_CONFORMANCE_SRC_COMBAT_JS = """export function clamp(value, minimum, maximum) {
  if (value < minimum) return minimum;
  if (value > maximum) return maximum;
  return value;
}

export function applyDamage(health, amount) {
  const value = Number(amount);
  if (!Number.isFinite(value) || value <= 0) return health;
  return clamp(health - value, 0, health);
}

export function createProjectile({ id, x, y, angle, speed }) {
  return {
    id,
    x,
    y,
    dx: Math.cos(angle) * speed,
    dy: Math.sin(angle) * speed,
    lifeMs: 900,
  };
}

export function stepProjectile(projectile, deltaMs) {
  const seconds = deltaMs / 1000;
  return {
    ...projectile,
    x: projectile.x + projectile.dx * seconds,
    y: projectile.y + projectile.dy * seconds,
    lifeMs: projectile.lifeMs - deltaMs,
  };
}
"""

_CONFORMANCE_SRC_UPGRADES_JS = """export const UPGRADE_CATALOG = Object.freeze([
  Object.freeze({ id: 'relay-tuning', name: 'Relay Tuning', description: 'Relay charge accrues faster.' }),
  Object.freeze({ id: 'kinetic-plating', name: 'Kinetic Plating', description: 'Raises maximum integrity.' }),
  Object.freeze({ id: 'phase-dash', name: 'Phase Dash', description: 'Shortens the dash cooldown.' }),
  Object.freeze({ id: 'overcharge', name: 'Overcharge', description: 'Projectiles strike harder.' }),
  Object.freeze({ id: 'signal-echo', name: 'Signal Echo', description: 'Reveals contesting enemies sooner.' }),
  Object.freeze({ id: 'coolant-loop', name: 'Coolant Loop', description: 'Reduces contact damage taken.' }),
]);

export function offerUpgrades(applied, random) {
  const pool = UPGRADE_CATALOG.filter((entry) => !applied.includes(entry.id));
  const chosen = [];
  const remaining = pool.slice();
  while (chosen.length < 3 && remaining.length > 0) {
    const index = Math.floor(random.next() * remaining.length) % remaining.length;
    chosen.push(remaining[index]);
    remaining.splice(index, 1);
  }
  return chosen;
}

export function upgradeEffect(id) {
  if (id === 'relay-tuning') return { chargeMultiplier: 1.25 };
  if (id === 'kinetic-plating') return { maxHealthBonus: 1 };
  if (id === 'phase-dash') return { dashCooldownMultiplier: 0.8 };
  if (id === 'overcharge') return { damageBonus: 1 };
  if (id === 'signal-echo') return { revealBonus: 1 };
  return { contactReduction: 1 };
}
"""

_CONFORMANCE_SRC_GAME_JS = """import { createRandom } from './random.js';
import { STATES } from './state-machine.js';
import { ARENA, RELAY_ZONES, createEnemy, createPlayer, createRelays, isArchetype, listArchetypes } from './entities.js';
import { applyDamage, clamp, createProjectile, stepProjectile } from './combat.js';
import { offerUpgrades, upgradeEffect } from './upgrades.js';

const RELAY_FULL_CHARGE = 100;
const RELAY_MS_TO_FULL = 5000;
const MAX_ENEMIES = 12;
const BOSS_HEALTH = 30;

export function createGame(options = {}) {
  const requested = Number(options && options.seed);
  const seed = Number.isFinite(requested) ? requested : 1;

  let random;
  let state;
  let timeMs;
  let player;
  let relays;
  let activeRelayIndex;
  let enemies;
  let projectiles;
  let boss;
  let applied;
  let pending;
  let events;
  let nextId;
  let occupied;
  let chargeMultiplier;

  function reset() {
    random = createRandom(seed);
    state = STATES.TITLE;
    timeMs = 0;
    player = createPlayer();
    relays = createRelays(RELAY_FULL_CHARGE);
    activeRelayIndex = 0;
    enemies = [];
    projectiles = [];
    boss = null;
    applied = [];
    pending = [];
    events = [];
    nextId = 1;
    occupied = false;
    chargeMultiplier = 1;
  }

  reset();

  function record(type, payload) {
    events.push({ type, timeMs, ...payload });
  }

  function contested(index) {
    return enemies.some((enemy) => enemy.relayIndex === index && enemy.health > 0);
  }

  function relaysComplete() {
    return relays.filter((relay) => relay.complete).length;
  }

  function addEnemy(type, generation, relayIndex) {
    if (enemies.length >= MAX_ENEMIES) return null;
    const zone = RELAY_ZONES[relayIndex];
    const enemy = createEnemy({
      id: 'e' + nextId,
      type,
      generation,
      relayIndex,
      x: clamp(zone.x + (random.next() - 0.5) * zone.radius, 0, ARENA.width),
      y: clamp(zone.y + (random.next() - 0.5) * zone.radius, 0, ARENA.height),
    });
    if (enemy === null) return null;
    nextId += 1;
    enemies.push(enemy);
    record('enemy-spawned', { enemyId: enemy.id, enemyType: type, generation });
    return { ...enemy };
  }

  function finishRelay() {
    const relay = relays[activeRelayIndex];
    relay.complete = true;
    relay.charge = relay.fullCharge;
    occupied = false;
    enemies = enemies.filter((enemy) => enemy.relayIndex !== relay.index);
    record('relay-complete', { relayIndex: relay.index });
    const completed = relaysComplete();
    if (completed >= relays.length) {
      boss = { health: BOSS_HEALTH, maxHealth: BOSS_HEALTH, active: true };
      record('boss-activated', { health: BOSS_HEALTH });
      return;
    }
    activeRelayIndex = completed;
    pending = offerUpgrades(applied, random);
    state = STATES.UPGRADE;
    record('upgrade-offered', { choices: pending.map((choice) => choice.id) });
  }

  return {
    start() {
      if (state !== STATES.TITLE) return false;
      state = STATES.RUNNING;
      record('run-started', { seed });
      return true;
    },

    pause() {
      if (state !== STATES.RUNNING) return false;
      state = STATES.PAUSED;
      record('paused', {});
      return true;
    },

    resume() {
      if (state !== STATES.PAUSED) return false;
      state = STATES.RUNNING;
      record('resumed', {});
      return true;
    },

    restart() {
      if (state !== STATES.GAME_OVER && state !== STATES.VICTORY) return false;
      reset();
      return true;
    },

    advance(deltaMs) {
      if (state !== STATES.RUNNING) return false;
      const delta = Number(deltaMs);
      if (!Number.isFinite(delta) || delta <= 0) return false;
      timeMs += delta;
      player.dashCooldownMs = Math.max(0, player.dashCooldownMs - delta);
      projectiles = projectiles
        .map((projectile) => stepProjectile(projectile, delta))
        .filter((projectile) => projectile.lifeMs > 0);
      const relay = relays[activeRelayIndex];
      if (relay && !relay.complete && occupied && !contested(activeRelayIndex)) {
        const rate = (relay.fullCharge / RELAY_MS_TO_FULL) * chargeMultiplier;
        const charged = Math.min(relay.fullCharge, relay.charge + delta * rate);
        relay.charge = charged;
        if (charged >= relay.fullCharge) finishRelay();
      }
      return true;
    },

    dash() {
      if (state !== STATES.RUNNING) return false;
      if (player.dashCooldownMs > 0) return false;
      player.dashCooldownMs = player.dashCooldownTotalMs;
      const angle = random.next() * Math.PI * 2;
      player.x = clamp(player.x + Math.cos(angle) * 64, 0, ARENA.width);
      player.y = clamp(player.y + Math.sin(angle) * 64, 0, ARENA.height);
      record('dash', {});
      return true;
    },

    fire(angle) {
      if (state !== STATES.RUNNING) return null;
      const direction = Number(angle);
      if (!Number.isFinite(direction)) return null;
      const projectile = createProjectile({
        id: 'p' + nextId,
        x: player.x,
        y: player.y,
        angle: direction,
        speed: 520,
      });
      nextId += 1;
      projectiles.push(projectile);
      record('fired', { projectileId: projectile.id });
      return { ...projectile };
    },

    spawnEnemy(type) {
      if (state !== STATES.RUNNING) return null;
      if (!isArchetype(type)) return null;
      if (enemies.length >= MAX_ENEMIES) return null;
      return addEnemy(type, 0, activeRelayIndex);
    },

    damageEnemy(id, amount) {
      if (state !== STATES.RUNNING) return false;
      const value = Number(amount);
      if (!Number.isFinite(value) || value <= 0) return false;
      const index = enemies.findIndex((enemy) => enemy.id === id && enemy.health > 0);
      if (index < 0) return false;
      const enemy = enemies[index];
      enemy.health = applyDamage(enemy.health, value);
      record('enemy-damaged', { enemyId: enemy.id, health: enemy.health });
      if (enemy.health === 0) {
        enemies.splice(index, 1);
        record('enemy-killed', { enemyId: enemy.id, enemyType: enemy.type, generation: enemy.generation });
        if (enemy.type === 'splitter' && enemy.generation === 0) {
          addEnemy('splitter', 1, enemy.relayIndex);
          addEnemy('splitter', 1, enemy.relayIndex);
        }
      }
      return true;
    },

    damagePlayer(amount) {
      if (state !== STATES.RUNNING) return false;
      const value = Number(amount);
      if (!Number.isFinite(value) || value <= 0) return false;
      player.health = applyDamage(player.health, value);
      record('player-damaged', { health: player.health });
      if (player.health === 0) {
        state = STATES.GAME_OVER;
        record('game-over', {});
      }
      return true;
    },

    enterRelayZone() {
      if (state !== STATES.RUNNING) return false;
      if (occupied) return false;
      occupied = true;
      record('relay-entered', { relayIndex: activeRelayIndex });
      return true;
    },

    leaveRelayZone() {
      if (state !== STATES.RUNNING) return false;
      if (!occupied) return false;
      occupied = false;
      record('relay-left', { relayIndex: activeRelayIndex });
      return true;
    },

    removeEnemy(id) {
      if (state !== STATES.RUNNING) return false;
      const index = enemies.findIndex((enemy) => enemy.id === id);
      if (index < 0) return false;
      const [removed] = enemies.splice(index, 1);
      record('enemy-removed', { enemyId: removed.id });
      return true;
    },

    completeRelay() {
      if (state !== STATES.RUNNING) return false;
      const relay = relays[activeRelayIndex];
      if (!relay || relay.complete) return false;
      finishRelay();
      return true;
    },

    availableUpgrades() {
      if (state !== STATES.UPGRADE) return [];
      return pending.map((choice) => ({
        id: choice.id,
        name: choice.name,
        description: choice.description,
      }));
    },

    applyUpgrade(id) {
      if (state !== STATES.UPGRADE) return false;
      const choice = pending.find((entry) => entry.id === id);
      if (!choice) return false;
      if (applied.includes(choice.id)) return false;
      applied.push(choice.id);
      const effect = upgradeEffect(choice.id);
      if (effect.chargeMultiplier) chargeMultiplier *= effect.chargeMultiplier;
      if (effect.maxHealthBonus) player.maxHealth += effect.maxHealthBonus;
      if (effect.dashCooldownMultiplier) {
        player.dashCooldownTotalMs = Math.round(player.dashCooldownTotalMs * effect.dashCooldownMultiplier);
      }
      pending = [];
      state = STATES.RUNNING;
      record('upgrade-applied', { upgradeId: choice.id });
      return true;
    },

    damageBoss(amount) {
      if (state !== STATES.RUNNING) return false;
      if (boss === null || !boss.active) return false;
      const value = Number(amount);
      if (!Number.isFinite(value) || value <= 0) return false;
      boss.health = applyDamage(boss.health, value);
      record('boss-damaged', { health: boss.health });
      if (boss.health === 0) {
        boss.active = false;
        if (relays.every((relay) => relay.complete)) {
          state = STATES.VICTORY;
          record('victory', {});
        }
      }
      return true;
    },

    listEnemyTypes() {
      return listArchetypes();
    },

    getEvents() {
      return events.map((event) => ({ ...event }));
    },

    getState() {
      return {
        state,
        timeMs,
        arena: { width: ARENA.width, height: ARENA.height },
        player: {
          health: player.health,
          maxHealth: player.maxHealth,
          x: player.x,
          y: player.y,
          dashCooldownMs: player.dashCooldownMs,
          dashCooldownTotalMs: player.dashCooldownTotalMs,
        },
        relays: relays.map((relay) => ({
          index: relay.index,
          charge: relay.charge,
          fullCharge: relay.fullCharge,
          complete: relay.complete,
          contested: contested(relay.index),
          occupied: occupied && relay.index === activeRelayIndex && !relay.complete,
        })),
        activeRelayIndex,
        relaysComplete: relaysComplete(),
        enemies: enemies.map((enemy) => ({
          id: enemy.id,
          type: enemy.type,
          health: enemy.health,
          generation: enemy.generation,
          x: enemy.x,
          y: enemy.y,
        })),
        maxEnemies: MAX_ENEMIES,
        projectiles: projectiles.map((projectile) => ({ ...projectile })),
        boss: boss === null ? null : { health: boss.health, maxHealth: boss.maxHealth, active: boss.active },
        appliedUpgrades: applied.slice(),
        pendingUpgradeChoices: pending.map((choice) => choice.id),
      };
    },
  };
}
"""

_CONFORMANCE_SRC_RENDER_JS = """import { STATES } from './state-machine.js';

const PALETTE = {
  player: '#4ff8ff',
  chaser: '#ff4fd8',
  shooter: '#ffd04f',
  splitter: '#7dff8a',
  boss: '#ff6b4f',
  relay: '#4f8dff',
};

export function createRenderer(canvas, overlays, hud) {
  const context = canvas.getContext('2d');

  function drawRelay(relay) {
    context.strokeStyle = relay.complete ? PALETTE.splitter : relay.contested ? PALETTE.boss : PALETTE.relay;
    context.lineWidth = relay.contested ? 4 : 2;
    context.beginPath();
    context.arc(320 + relay.index * 320, 220 + relay.index * 120, 120, 0, Math.PI * 2);
    context.stroke();
    context.fillStyle = PALETTE.relay;
    context.fillRect(200 + relay.index * 320, 360 + relay.index * 120, (relay.charge / relay.fullCharge) * 240, 8);
  }

  return {
    draw(snapshot) {
      context.clearRect(0, 0, canvas.width, canvas.height);
      context.fillStyle = '#070a18';
      context.fillRect(0, 0, canvas.width, canvas.height);
      snapshot.relays.forEach(drawRelay);
      for (const projectile of snapshot.projectiles) {
        context.fillStyle = PALETTE.player;
        context.fillRect(projectile.x - 2, projectile.y - 2, 4, 4);
      }
      for (const enemy of snapshot.enemies) {
        context.fillStyle = PALETTE[enemy.type] || PALETTE.chaser;
        const size = enemy.generation > 0 ? 8 : 14;
        if (enemy.type === 'chaser') context.fillRect(enemy.x - size / 2, enemy.y - size / 2, size, size);
        else {
          context.beginPath();
          context.arc(enemy.x, enemy.y, size / 2, 0, Math.PI * 2);
          context.fill();
        }
      }
      if (snapshot.boss) {
        context.fillStyle = PALETTE.boss;
        context.fillRect(canvas.width / 2 - 40, 40, 80 * (snapshot.boss.health / snapshot.boss.maxHealth), 20);
      }
      context.fillStyle = PALETTE.player;
      context.beginPath();
      context.arc(snapshot.player.x, snapshot.player.y, 10, 0, Math.PI * 2);
      context.fill();
      hud.health.textContent = 'Integrity ' + snapshot.player.health + '/' + snapshot.player.maxHealth;
      hud.dash.textContent = snapshot.player.dashCooldownMs === 0 ? 'Dash ready' : 'Dash ' + Math.ceil(snapshot.player.dashCooldownMs) + 'ms';
      hud.relay.textContent = 'Charge ' + Math.round(snapshot.relays[snapshot.activeRelayIndex].charge);
      hud.sector.textContent = 'Sector ' + (snapshot.relaysComplete + 1) + '/3';
      for (const [key, element] of Object.entries(overlays)) {
        element.classList.toggle('hidden', key !== snapshot.state);
      }
      if (snapshot.state === STATES.UPGRADE) {
        overlays[STATES.UPGRADE].classList.remove('hidden');
      }
    },
  };
}
"""

_CONFORMANCE_SRC_MAIN_JS = """import { createGame } from './game.js';
import { STATES } from './state-machine.js';
import { createRenderer } from './render.js';

const canvas = document.getElementById('arena');
const hud = {
  health: document.getElementById('hud-health'),
  dash: document.getElementById('hud-dash'),
  relay: document.getElementById('hud-relay'),
  sector: document.getElementById('hud-sector'),
};
const overlays = {
  [STATES.TITLE]: document.getElementById('overlay-title'),
  [STATES.RUNNING]: document.getElementById('hud'),
  [STATES.PAUSED]: document.getElementById('overlay-pause'),
  [STATES.UPGRADE]: document.getElementById('overlay-upgrade'),
  [STATES.GAME_OVER]: document.getElementById('overlay-over'),
  [STATES.VICTORY]: document.getElementById('overlay-victory'),
};

const game = createGame({ seed: 20260727 });
const renderer = createRenderer(canvas, overlays, hud);
const held = new Set();
let last = null;
let aim = 0;

window.addEventListener('keydown', (event) => {
  const key = event.key.toLowerCase();
  held.add(key);
  if (key === 'enter') game.start();
  if (key === 'p') {
    if (game.getState().state === STATES.RUNNING) game.pause();
    else game.resume();
  }
  if (key === 'r') game.restart();
  if (key === ' ') game.dash();
});

window.addEventListener('keyup', (event) => held.delete(event.key.toLowerCase()));

canvas.addEventListener('mousemove', (event) => {
  const bounds = canvas.getBoundingClientRect();
  const snapshot = game.getState();
  aim = Math.atan2(event.clientY - bounds.top - snapshot.player.y, event.clientX - bounds.left - snapshot.player.x);
});

canvas.addEventListener('mousedown', (event) => {
  if (event.button === 0) game.fire(aim);
});

function frame(now) {
  if (last !== null) game.advance(Math.min(48, now - last));
  last = now;
  renderer.draw(game.getState());
  window.requestAnimationFrame(frame);
}

window.requestAnimationFrame(frame);
"""

_CONFORMANCE_TEST_GAME_JS = """import test from 'node:test';
import assert from 'node:assert/strict';

import { createGame } from '../src/game.js';

test('a run starts, pauses and resumes without advancing while paused', () => {
  const game = createGame({ seed: 1 });
  assert.equal(game.getState().state, 'TITLE');
  game.start();
  game.advance(100);
  game.pause();
  const paused = game.getState().timeMs;
  game.advance(1000);
  assert.equal(game.getState().timeMs, paused);
  game.resume();
  game.advance(50);
  assert.ok(game.getState().timeMs > paused);
});

test('a relay charges only while occupied and uncontested', () => {
  const game = createGame({ seed: 2 });
  game.start();
  game.advance(500);
  assert.equal(game.getState().relays[0].charge, 0);
  game.enterRelayZone();
  game.advance(500);
  const charged = game.getState().relays[0].charge;
  assert.ok(charged > 0);
  const enemy = game.spawnEnemy('chaser');
  game.advance(1000);
  assert.ok(game.getState().relays[0].charge <= charged);
  game.removeEnemy(enemy.id);
  game.advance(500);
  assert.ok(game.getState().relays[0].charge > charged);
});

test('dash respects its cooldown', () => {
  const game = createGame({ seed: 3 });
  game.start();
  assert.equal(game.dash(), true);
  assert.equal(game.dash(), false);
  game.advance(game.getState().player.dashCooldownTotalMs);
  assert.equal(game.dash(), true);
});

test('an upgrade applies once per offer and restart resets the run', () => {
  const game = createGame({ seed: 4 });
  game.start();
  game.completeRelay();
  const choices = game.availableUpgrades();
  assert.equal(choices.length, 3);
  assert.equal(game.applyUpgrade(choices[0].id), true);
  assert.equal(game.applyUpgrade(choices[0].id), false);
  game.damagePlayer(1000);
  assert.equal(game.getState().state, 'GAME_OVER');
  game.restart();
  const after = game.getState();
  assert.equal(after.state, 'TITLE');
  assert.equal(after.appliedUpgrades.length, 0);
  assert.equal(after.player.health, after.player.maxHealth);
});

test('a generation-zero splitter divides exactly once', () => {
  const game = createGame({ seed: 5 });
  game.start();
  const parent = game.spawnEnemy('splitter');
  game.damageEnemy(parent.id, parent.health);
  const children = game.getState().enemies;
  assert.equal(children.length, 2);
  game.damageEnemy(children[0].id, children[0].health);
  assert.equal(game.getState().enemies.length, 1);
});

test('victory needs three relays and a dead boss', () => {
  const game = createGame({ seed: 6 });
  game.start();
  for (let index = 0; index < 2; index += 1) {
    game.completeRelay();
    game.applyUpgrade(game.availableUpgrades()[0].id);
  }
  game.completeRelay();
  const boss = game.getState().boss;
  assert.ok(boss.active);
  assert.notEqual(game.getState().state, 'VICTORY');
  game.damageBoss(boss.maxHealth);
  assert.equal(game.getState().state, 'VICTORY');
});
"""

_CONFORMANCE_TEST_STATE_MACHINE_JS = """import test from 'node:test';
import assert from 'node:assert/strict';

import { STATES, canTransition, legalTransitions } from '../src/state-machine.js';

test('the six domain states are exact', () => {
  assert.deepEqual(Object.keys(STATES).sort(), [
    'GAME_OVER',
    'PAUSED',
    'RUNNING',
    'TITLE',
    'UPGRADE',
    'VICTORY',
  ]);
  assert.equal(STATES.RUNNING, 'RUNNING');
});

test('pause, resume and upgrade transitions are legal', () => {
  assert.equal(canTransition('RUNNING', 'PAUSED'), true);
  assert.equal(canTransition('PAUSED', 'RUNNING'), true);
  assert.equal(canTransition('RUNNING', 'UPGRADE'), true);
  assert.equal(canTransition('UPGRADE', 'RUNNING'), true);
});

test('restart transitions leave the terminal states only', () => {
  assert.equal(canTransition('GAME_OVER', 'TITLE'), true);
  assert.equal(canTransition('VICTORY', 'TITLE'), true);
  assert.equal(canTransition('GAME_OVER', 'RUNNING'), false);
});

test('dash and relay states cannot be smuggled in', () => {
  assert.equal(canTransition('TITLE', 'PAUSED'), false);
  assert.equal(canTransition('PAUSED', 'UPGRADE'), false);
  assert.equal(legalTransitions().length, 9);
});
"""

CONFORMANCE_FILES: dict[str, str] = {
    "package.json": _CONFORMANCE_PACKAGE_JSON,
    "LOCAL_DEV.md": _CONFORMANCE_LOCAL_DEV_MD,
    "index.html": _CONFORMANCE_INDEX_HTML,
    "style.css": _CONFORMANCE_STYLE_CSS,
    "src/random.js": _CONFORMANCE_SRC_RANDOM_JS,
    "src/state-machine.js": _CONFORMANCE_SRC_STATE_MACHINE_JS,
    "src/entities.js": _CONFORMANCE_SRC_ENTITIES_JS,
    "src/combat.js": _CONFORMANCE_SRC_COMBAT_JS,
    "src/upgrades.js": _CONFORMANCE_SRC_UPGRADES_JS,
    "src/game.js": _CONFORMANCE_SRC_GAME_JS,
    "src/render.js": _CONFORMANCE_SRC_RENDER_JS,
    "src/main.js": _CONFORMANCE_SRC_MAIN_JS,
    "test/game.test.js": _CONFORMANCE_TEST_GAME_JS,
    "test/state-machine.test.js": _CONFORMANCE_TEST_STATE_MACHINE_JS,
}


# ---------------------------------------------------------------------------
# Twenty external clause mutations.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Mutation:
    """One bounded external mutation and the clause that must kill it."""

    mutation_id: str
    description: str
    intended_clause: str
    path: str
    old: str
    new: str
    extra_old: str | None = None
    extra_new: str | None = None
    mutates_verifier: bool = False
    replace_whole_file: bool = False
    delete_path: bool = False
    base_mutation: str | None = None


_PLACEHOLDER_TEST = """import test from 'node:test';

test('game placeholder', () => {});

test('another placeholder', () => {});
"""

MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "MUT-01",
        "uncontrolled Math.random replaces the seeded generator in the dash",
        "C04_domain_is_pure",
        "src/game.js",
        "const angle = random.next() * Math.PI * 2;",
        "const angle = Math.random() * Math.PI * 2;",
    ),
    Mutation(
        "MUT-02",
        "a paused simulation keeps advancing",
        "C08_paused_does_not_progress",
        "src/game.js",
        """    advance(deltaMs) {
      if (state !== STATES.RUNNING) return false;""",
        """    advance(deltaMs) {
      if (state !== STATES.RUNNING && state !== STATES.PAUSED) return false;""",
    ),
    Mutation(
        "MUT-03",
        "restart retains every applied upgrade",
        "C09_restart_resets",
        "src/game.js",
        """      if (state !== STATES.GAME_OVER && state !== STATES.VICTORY) return false;
      reset();
      return true;""",
        """      if (state !== STATES.GAME_OVER && state !== STATES.VICTORY) return false;
      const retained = applied.slice();
      reset();
      applied = retained;
      return true;""",
    ),
    Mutation(
        "MUT-04",
        "an illegal GAME_OVER to RUNNING transition is accepted",
        "C10_legal_transitions",
        "src/state-machine.js",
        "  Object.freeze(['GAME_OVER', 'TITLE']),",
        "  Object.freeze(['GAME_OVER', 'TITLE']),\n  Object.freeze(['GAME_OVER', 'RUNNING']),",
    ),
    Mutation(
        "MUT-05",
        "the dash bypasses its cooldown",
        "C11_dash_cooldown_bounded",
        "src/game.js",
        """      if (state !== STATES.RUNNING) return false;
      if (player.dashCooldownMs > 0) return false;
      player.dashCooldownMs = player.dashCooldownTotalMs;""",
        """      if (state !== STATES.RUNNING) return false;
      player.dashCooldownMs = player.dashCooldownTotalMs;""",
    ),
    Mutation(
        "MUT-06",
        "one upgrade can be applied twice from the same offer",
        "C12_upgrade_applied_once",
        "src/game.js",
        """    applyUpgrade(id) {
      if (state !== STATES.UPGRADE) return false;
      const choice = pending.find((entry) => entry.id === id);
      if (!choice) return false;
      if (applied.includes(choice.id)) return false;
      applied.push(choice.id);""",
        """    applyUpgrade(id) {
      if (state !== STATES.UPGRADE && state !== STATES.RUNNING) return false;
      const choice = pending.find((entry) => entry.id === id);
      if (!choice) return false;
      applied.push(choice.id);""",
        extra_old="""      pending = [];
      state = STATES.RUNNING;
      record('upgrade-applied', { upgradeId: choice.id });""",
        extra_new="""      state = STATES.RUNNING;
      record('upgrade-applied', { upgradeId: choice.id });""",
    ),
    Mutation(
        "MUT-07",
        "a generation-one splitter divides again",
        "C13_splitter_divides_once",
        "src/game.js",
        "if (enemy.type === 'splitter' && enemy.generation === 0) {",
        "if (enemy.type === 'splitter' && enemy.generation <= 1) {",
    ),
    Mutation(
        "MUT-08",
        "a contested relay keeps gaining charge",
        "C14_relay_contesting_law",
        "src/game.js",
        "if (relay && !relay.complete && occupied && !contested(activeRelayIndex)) {",
        "if (relay && !relay.complete && occupied) {",
    ),
    Mutation(
        "MUT-09",
        "the simulation keeps progressing after game over",
        "C15_game_over_stops_simulation",
        "src/game.js",
        """    advance(deltaMs) {
      if (state !== STATES.RUNNING) return false;""",
        """    advance(deltaMs) {
      if (state !== STATES.RUNNING && state !== STATES.GAME_OVER) return false;""",
    ),
    Mutation(
        "MUT-10",
        "victory is declared when the boss appears rather than when it dies",
        "C16_victory_requires_relays_and_boss",
        "src/game.js",
        """      boss = { health: BOSS_HEALTH, maxHealth: BOSS_HEALTH, active: true };
      record('boss-activated', { health: BOSS_HEALTH });
      return;""",
        """      boss = { health: BOSS_HEALTH, maxHealth: BOSS_HEALTH, active: true };
      record('boss-activated', { health: BOSS_HEALTH });
      state = STATES.VICTORY;
      record('victory', {});
      return;""",
    ),
    Mutation(
        "MUT-11",
        "the enemy count exceeds maxEnemies",
        "C17_entity_bounds",
        "src/game.js",
        """      if (!isArchetype(type)) return null;
      if (enemies.length >= MAX_ENEMIES) return null;
      return addEnemy(type, 0, activeRelayIndex);""",
        """      if (!isArchetype(type)) return null;
      return addEnemy(type, 0, activeRelayIndex);""",
        extra_old="""  function addEnemy(type, generation, relayIndex) {
    if (enemies.length >= MAX_ENEMIES) return null;
""",
        extra_new="""  function addEnemy(type, generation, relayIndex) {
""",
    ),
    Mutation(
        "MUT-12",
        "one required enemy archetype is absent from the exposed set",
        "C18_enemy_archetypes",
        "src/entities.js",
        """export function listArchetypes() {
  return Object.keys(ENEMY_ARCHETYPES);
}""",
        """export function listArchetypes() {
  return Object.keys(ENEMY_ARCHETYPES).filter((id) => id !== 'shooter');
}""",
    ),
    Mutation(
        "MUT-13",
        "a start script that runs a server exists",
        "C02_package_contract",
        "package.json",
        '    "test": "node --test test/"',
        '    "start": "node local-server.mjs",\n    "test": "node --test test/"',
    ),
    Mutation(
        "MUT-14",
        "an external URL is fetched at runtime",
        "C03_no_external_runtime",
        "src/main.js",
        "function frame(now) {",
        """async function reportScore(value) {
  await fetch('https://leaderboard.example.com/neon-relay', {
    method: 'POST',
    body: String(value),
  });
}

function frame(now) {""",
    ),
    Mutation(
        "MUT-15",
        "the agent tests contain no meaningful assertion",
        "C05_agent_tests_are_behavioural",
        "test/game.test.js",
        "",
        _PLACEHOLDER_TEST,
        replace_whole_file=True,
    ),
    Mutation(
        "MUT-16",
        "a required material path is absent",
        "C01_required_paths",
        "style.css",
        "",
        "",
        delete_path=True,
    ),
    Mutation(
        "MUT-17",
        "a domain module imports the renderer",
        "C04_domain_is_pure",
        "src/game.js",
        "import { offerUpgrades, upgradeEffect } from './upgrades.js';",
        "import { offerUpgrades, upgradeEffect } from './upgrades.js';\nimport { createRenderer } from './render.js';",
    ),
    Mutation(
        "MUT-18",
        "the index document has no canvas",
        "C03_no_external_runtime",
        "index.html",
        '      <canvas id="arena" width="1280" height="720" aria-label="Neon Relay arena"></canvas>\n',
        "",
    ),
    Mutation(
        "MUT-19",
        "the blank fixture marker remains in the documentation",
        "C03_no_external_runtime",
        "LOCAL_DEV.md",
        "# Local development\n",
        "# Local development\n\nFixture marker: `NEON_RELAY_BLANK_FIXTURE_V1`\n",
    ),
    Mutation(
        "MUT-20",
        "the verifier emits its success line despite a failed clause",
        "C01_required_paths",
        "verifier",
        "const ok = failed.length === 0;",
        "const ok = true;",
        mutates_verifier=True,
        base_mutation="MUT-16",
    ),
)


# ---------------------------------------------------------------------------
# Verifier execution helpers. They mirror the production behavioral-verifier
# invocation exactly: node with the frozen script and the workspace root as the
# sole positional argument.
# ---------------------------------------------------------------------------


def _node() -> str:
    return "node.exe" if os.name == "nt" else "node"


def _materialize(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return root


def _write_verifier(directory: Path, source: str = NEON_RELAY_VERIFIER_SOURCE) -> Path:
    script = directory / "neon-relay-verifier.mjs"
    script.write_bytes(source.encode("utf-8"))
    return script


def _execute(script: Path, workspace: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            _node(),
            "--preserve-symlinks",
            "--preserve-symlinks-main",
            str(script),
            str(workspace),
        ],
        cwd=str(script.parent),
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=NEON_RELAY_VERIFIER_TIMEOUT_SECONDS,
    )


def _report(completed: subprocess.CompletedProcess[str]) -> dict:
    assert completed.stdout, f"verifier produced no report; stderr={completed.stderr[:800]!r}"
    lines = completed.stdout.splitlines()
    payload = json.loads(lines[0])
    payload["_exit_code"] = completed.returncode
    payload["_success_line"] = NEON_RELAY_VERIFIER_SUCCESS_LINE in lines[1:]
    payload["_stderr"] = completed.stderr
    payload["_stdout_bytes"] = len(completed.stdout.encode("utf-8"))
    return payload


def _apply_mutation(root: Path, mutation: Mutation) -> None:
    target = root / mutation.path
    if mutation.delete_path:
        target.unlink()
        return
    if mutation.replace_whole_file:
        target.write_bytes(mutation.new.encode("utf-8"))
        return
    text = target.read_text(encoding="utf-8")
    edits = [(mutation.old, mutation.new)]
    if mutation.extra_old is not None:
        edits.append((mutation.extra_old, mutation.extra_new))
    for old, new in edits:
        assert text.count(old) == 1, (
            f"{mutation.mutation_id}: mutation anchor must appear exactly once in "
            f"{mutation.path}, observed {text.count(old)}"
        )
        text = text.replace(old, new)
    target.write_bytes(text.encode("utf-8"))


def _git(repository: Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    completed = subprocess.run(
        ["git", "--no-pager", *arguments],
        cwd=str(repository),
        env=environment,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, f"git {arguments} failed: {completed.stderr}"
    return completed.stdout


# ---------------------------------------------------------------------------
# Profile identity pins.
# ---------------------------------------------------------------------------


def test_profile_schema_and_identity_are_exact():
    assert PROFILE.schema_version == EXPECTED_SCHEMA_VERSION == MISSION_PROFILE_SCHEMA_VERSION_V2
    assert PROFILE.profile_id == EXPECTED_PROFILE_ID
    assert PROFILE.mission_id == EXPECTED_MISSION_ID
    assert PROFILE.gate_id == EXPECTED_GATE_ID
    assert PROFILE.run_id == EXPECTED_RUN_ID
    assert PROFILE.session_id == EXPECTED_SESSION_ID
    assert PROFILE.model == EXPECTED_MODEL
    assert PROFILE.is_launchable_runtime_profile is True
    assert PROFILE.has_nested_runtime_authority is True
    assert PROFILE.verification_mode is VerificationMode.FROZEN_BEHAVIORAL
    assert PROFILE.fixture_id is None and PROFILE.fixture_version is None
    assert PROFILE.fixture_initial_commit_message is None
    assert [clause[0] for clause in PROFILE.gate_clauses] == [
        "neon-relay.material",
        "neon-relay.git",
        "neon-relay.checkpoint",
        "neon-relay.behavior",
        "neon-relay.nonclaims",
        "neon-relay.human-visual-review",
    ]


def test_workspace_source_binds_the_exact_fixture_path():
    source = PROFILE.effective_workspace_source
    assert source.kind is WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY
    assert source.local_repository_path == EXPECTED_FIXTURE_PATH
    assert source.local_repository_path == NEON_RELAY_FIXTURE_REPOSITORY_PATH
    assert source.fixture_id is None and source.fixture_version is None
    assert Path(source.local_repository_path).is_absolute()


def test_budgets_checkpoint_and_process_bounds_are_exact():
    assert PROFILE.budgets == ONE_SHOT_PROFILE_BUDGETS == (1, 1, 0, 0, 0)
    assert PROFILE.timeout_seconds == EXPECTED_TIMEOUT_SECONDS == 2700
    assert PROFILE.stdout_byte_limit == EXPECTED_STDOUT_BYTE_LIMIT == 8_388_608
    assert PROFILE.stderr_byte_limit == EXPECTED_STDERR_BYTE_LIMIT == 1_048_576
    assert len(PROFILE.checkpoint_commands) == 1
    checkpoint = PROFILE.checkpoint_commands[0]
    assert checkpoint.command_id == "npm-test"
    assert checkpoint.argv == ("npm.cmd", "test")
    assert checkpoint.timeout_seconds == 300
    assert checkpoint.max_capture_bytes == 1_048_576
    # The one checkpoint is a terminating command: no start, watch, server,
    # port probe, browser subprocess or repair invocation is configured.
    argv_text = " ".join(checkpoint.argv)
    for forbidden in ("start", "watch", "serve", "listen", "--port", "chrome", "repair"):
        assert forbidden not in argv_text
    assert PROFILE.budgets[2] == 0, "no repair round may be budgeted"


def test_git_end_state_policy_and_required_paths_are_exact_and_ordered():
    policy = PROFILE.effective_git_end_state_policy
    assert policy.required_commits_added == 1
    assert policy.required_complete_commit_message == NEON_RELAY_REQUIRED_COMMIT_MESSAGE
    assert policy.required_complete_commit_message == "feat: build playable Neon Relay browser game"
    assert "\n" not in policy.required_complete_commit_message
    assert policy.final_worktree_clean is True
    assert policy.final_index_clean is True
    assert policy.final_remotes_absent is True
    assert policy.required_material_paths == (
        "LOCAL_DEV.md",
        "index.html",
        "package.json",
        "style.css",
        "src/random.js",
        "src/state-machine.js",
        "src/entities.js",
        "src/combat.js",
        "src/upgrades.js",
        "src/game.js",
        "src/render.js",
        "src/main.js",
        "test/game.test.js",
        "test/state-machine.test.js",
    )
    assert policy.required_material_paths == NEON_RELAY_REQUIRED_MATERIAL_PATHS
    assert len(policy.required_material_paths) == 14
    assert "README.md" not in policy.required_material_paths
    assert PROFILE.required_material_paths == policy.required_material_paths


def test_mission_and_completion_condition_text_digests_are_exact():
    assert hashlib.sha256(NEON_RELAY_MISSION_TEXT.encode("utf-8")).hexdigest() == (
        EXPECTED_MISSION_TEXT_SHA256
    )
    assert NEON_RELAY_MISSION_TEXT_SHA256 == EXPECTED_MISSION_TEXT_SHA256
    assert PROFILE.mission_text == NEON_RELAY_MISSION_TEXT
    assert hashlib.sha256(NEON_RELAY_COMPLETION_CONDITIONS_TEXT.encode("utf-8")).hexdigest() == (
        EXPECTED_COMPLETION_CONDITIONS_SHA256
    )
    assert NEON_RELAY_COMPLETION_CONDITIONS_SHA256 == EXPECTED_COMPLETION_CONDITIONS_SHA256
    assert PROFILE.completion_conditions_text == NEON_RELAY_COMPLETION_CONDITIONS_TEXT
    # The completion conditions separate the six required groups and refuse
    # provider prose as a completion authority.
    for heading in (
        "1. Material presence and change",
        "2. Exact Git state",
        "3. Public checkpoint",
        "4. Frozen behavioral verification",
        "5. Bounded non-claims",
        "6. Human-only visual review",
    ):
        assert heading in NEON_RELAY_COMPLETION_CONDITIONS_TEXT
    assert "Provider prose establishes none of the above." in NEON_RELAY_COMPLETION_CONDITIONS_TEXT


def test_mission_text_states_the_exact_domain_contract():
    for state in NEON_RELAY_STATES:
        assert state in NEON_RELAY_MISSION_TEXT
    for enemy in NEON_RELAY_ENEMY_TYPES:
        assert enemy in NEON_RELAY_MISSION_TEXT
    for operation in NEON_RELAY_OPERATIONS:
        assert operation in NEON_RELAY_MISSION_TEXT
    for symbol in ("createRandom(seed)", "STATES", "legalTransitions()", "canTransition(from, to)", "createGame(options)"):
        assert symbol in NEON_RELAY_MISSION_TEXT
    assert "advance(deltaMs)" in NEON_RELAY_MISSION_TEXT
    for module_path in NEON_RELAY_DOMAIN_MODULE_PATHS:
        assert module_path in NEON_RELAY_MISSION_TEXT
        assert module_path in NEON_RELAY_REQUIRED_MATERIAL_PATHS
        assert module_path in NEON_RELAY_VERIFIER_SOURCE
    for forbidden in ("Date.now", "performance", "requestAnimationFrame", "document", "window", "localStorage", "Math.random"):
        assert forbidden in NEON_RELAY_MISSION_TEXT
    assert "npm start" not in NEON_RELAY_MISSION_TEXT


def test_verifier_authority_identity_and_disclosure_are_exact():
    verification = PROFILE.verification.validated()
    assert verification.mode is VerificationMode.FROZEN_BEHAVIORAL
    assert verification.verifier_source == NEON_RELAY_VERIFIER_SOURCE
    assert verification.verifier_source_sha256 == EXPECTED_VERIFIER_SOURCE_SHA256
    assert NEON_RELAY_VERIFIER_SOURCE_SHA256 == EXPECTED_VERIFIER_SOURCE_SHA256
    assert hashlib.sha256(NEON_RELAY_VERIFIER_SOURCE.encode("utf-8")).hexdigest() == (
        EXPECTED_VERIFIER_SOURCE_SHA256
    )
    assert verification.verifier_timeout_seconds == NEON_RELAY_VERIFIER_TIMEOUT_SECONDS == 180
    assert verification.verifier_output_limit_bytes == NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES == 262144
    assert verification.disclose_complete_source is True
    # The internal mirrors must agree with the nested authority.
    assert PROFILE.verifier_source == NEON_RELAY_VERIFIER_SOURCE
    assert PROFILE.verifier_source_sha256 == EXPECTED_VERIFIER_SOURCE_SHA256
    assert PROFILE.verifier_timeout_seconds == 180
    assert PROFILE.verifier_output_limit_bytes == 262144


def test_verifier_source_is_frozen_node_only_and_bounded():
    source = NEON_RELAY_VERIFIER_SOURCE
    # The verifier imports exactly three Node built-in modules and nothing else.
    import re as _re

    specifiers = sorted(set(_re.findall(r"^import[^\n]*?from '([^']+)';$", source, _re.MULTILINE)))
    assert specifiers == ["node:fs/promises", "node:path", "node:url"]
    assert _re.search(r"^import '", source, _re.MULTILINE) is None
    # The only dynamic import is the delivered domain module under the workspace
    # root; no subprocess, socket, server, browser or network form exists.
    assert source.count("await import(") == 1
    for forbidden in (
        "child_process",
        "node:net",
        "node:http",
        "node:https",
        "node:dgram",
        "node:worker_threads",
        "spawn(",
        "spawnSync",
        "execSync",
        "execFile",
        "createConnection(",
        "createServer(",
        "new WebSocket",
        "fetch(",
        "puppeteer",
        "chrome.exe",
        "require(",
        "npm.cmd",
    ):
        assert forbidden not in source, f"verifier must not use {forbidden!r}"
    # It never runs the agent-authored tests: they are only ever read as text.
    assert "'test/game.test.js'" in source and "'test/state-machine.test.js'" in source
    assert "DOMAIN_MODULES" in source
    for test_path in ("test/game.test.js", "test/state-machine.test.js"):
        assert f"'{test_path}'" not in source.split("const DOMAIN_MODULES")[1].split("];")[0]
    assert "process.argv[2]" in source
    assert "process.argv.length === 3" in source
    for clause_id in NEON_RELAY_VERIFIER_CLAUSE_IDS:
        assert f"'{clause_id}'" in source
    assert len(NEON_RELAY_VERIFIER_CLAUSE_IDS) == 18
    for non_claim in NEON_RELAY_VERIFIER_NON_CLAIMS:
        assert non_claim in source
    assert NEON_RELAY_VERIFIER_SUCCESS_LINE in source
    assert len(source.encode("utf-8")) <= 262144


def test_verifier_source_is_syntactically_valid_javascript(tmp_path: Path):
    script = _write_verifier(tmp_path)
    completed = subprocess.run(
        [_node(), "--check", str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr[:2000]


def test_profile_validates_and_round_trips_through_the_production_schema(tmp_path: Path):
    assert PROFILE.validated() == PROFILE
    assert NativeMissionProfile.from_dict(json.loads(json.dumps(PROFILE.to_dict()))) == PROFILE
    document = tmp_path / "neon-relay-v1.json"
    document.write_bytes(canonical_bytes(PROFILE.to_dict()) + b"\n")
    assert load_native_mission_profile_document(document.resolve()) == PROFILE


def test_profile_fingerprint_and_canonical_document_digest_are_exact():
    assert PROFILE.profile_fingerprint == EXPECTED_PROFILE_FINGERPRINT
    body = {key: value for key, value in PROFILE.to_dict().items() if key != "profile_fingerprint"}
    assert fingerprint(body) == EXPECTED_PROFILE_FINGERPRINT
    document = canonical_bytes(PROFILE.to_dict())
    assert hashlib.sha256(document).hexdigest() == EXPECTED_PROFILE_DOCUMENT_SHA256


def test_agent_prompt_discloses_the_complete_frozen_verifier_source():
    state = create_canary_session(session_id=PROFILE.session_id, profile=PROFILE)
    workspace = Path(r"C:\Users\stris\Documents\Projets\ENTRE") / PROFILE.run_id / "work"
    with mock.patch(
        "admissible.delegated_gate.native_canary._safe_directory",
        return_value=(workspace, None),
    ):
        prompt = build_native_agent_prompt(
            mission=state.mission,
            gate_contract=state.current_gate,
            work_workspace=workspace,
            required_commit_message=PROFILE.required_commit_message,
            completion_conditions=PROFILE.completion_conditions_text,
            profile=PROFILE,
        )
    assert "----- BEGIN OWNER-FROZEN BEHAVIORAL VERIFIER -----" in prompt
    assert NEON_RELAY_VERIFIER_SOURCE in prompt
    assert EXPECTED_VERIFIER_SOURCE_SHA256 in prompt
    assert NEON_RELAY_MISSION_TEXT in prompt
    assert NEON_RELAY_COMPLETION_CONDITIONS_TEXT in prompt
    assert "FROZEN_BEHAVIORAL" in prompt


# ---------------------------------------------------------------------------
# Fixture identity and workspace-source observation.
# ---------------------------------------------------------------------------


def test_fixture_observation_matches_the_bound_workspace_source_identity():
    fixture = Path(EXPECTED_FIXTURE_PATH)
    assert fixture.is_dir(), "the immutable Neon Relay fixture must exist at its bound path"
    observation = _observe_local_repository_source(fixture)
    assert observation.repository == EXPECTED_FIXTURE_PATH
    assert observation.head == EXPECTED_FIXTURE_HEAD
    assert observation.material_tree_hash == EXPECTED_FIXTURE_MATERIAL_TREE_HASH
    assert observation.worktree_material_tree_hash == EXPECTED_FIXTURE_MATERIAL_TREE_HASH
    assert observation.commit_count == 1
    assert observation.complete_commit_message == EXPECTED_FIXTURE_COMMIT_MESSAGE
    assert observation.porcelain_status == ""
    assert observation.remotes == ()
    identity = _initialized_identity_from_local_source(observation, PROFILE)
    assert identity.initial_git_head == EXPECTED_FIXTURE_HEAD
    assert identity.initial_material_tree_hash == EXPECTED_FIXTURE_MATERIAL_TREE_HASH
    assert identity.initial_commit_count == 1
    assert identity.initial_commit_message == EXPECTED_FIXTURE_COMMIT_MESSAGE
    assert identity.source_kind == WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY.value
    assert identity.source_identity == PROFILE.effective_workspace_source.identity_fingerprint


def test_fixture_git_state_is_the_pinned_single_blank_commit():
    fixture = Path(EXPECTED_FIXTURE_PATH)
    assert _git(fixture, "rev-parse", "HEAD").strip() == EXPECTED_FIXTURE_HEAD
    assert _git(fixture, "rev-parse", "HEAD^{tree}").strip() == EXPECTED_FIXTURE_GIT_TREE
    assert _git(fixture, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"
    assert _git(fixture, "rev-list", "--count", "HEAD").strip() == "1"
    assert _git(fixture, "remote", "-v") == ""
    assert _git(fixture, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert _git(fixture, "status", "--porcelain=v1", "--ignored=matching", "--untracked-files=all") == ""
    assert tuple(_git(fixture, "ls-files").split()) == EXPECTED_FIXTURE_TRACKED_PATHS
    assert not (fixture / ".gitmodules").exists()
    assert not (fixture / "node_modules").exists()
    # The blank fixture still carries the marker in both of its content files.
    assert NEON_RELAY_FIXTURE_MARKER in (fixture / "LOCAL_DEV.md").read_text(encoding="utf-8")
    assert NEON_RELAY_FIXTURE_MARKER in (fixture / "package.json").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def test_registration_adds_neon_relay_once_and_preserves_every_previous_identity():
    profiles = registered_profiles()
    identifiers = [profile.profile_id for profile in profiles.values()]
    assert identifiers.count(EXPECTED_PROFILE_ID) == 1
    assert profiles[EXPECTED_PROFILE_ID] == PROFILE
    assert profiles[EXPECTED_PROFILE_ID].profile_fingerprint == EXPECTED_PROFILE_FINGERPRINT
    assert resolve_registered_profile(EXPECTED_PROFILE_ID) == PROFILE
    for profile_id, digest in LEGACY_FINGERPRINTS.items():
        assert profiles[profile_id].profile_fingerprint == digest
    # The ACP transport repair registers neon-relay-v2 alongside v1 rather than
    # replacing it: v1's own identity above is unchanged, and v2 carries the
    # same mission on a new run identity because v1's argv transport cannot be
    # spawned on Windows and its single native attempt is durably consumed.
    # The backend-drift repair extends the registry the same way again: v2's own
    # single native attempt is durably consumed by the authorized run that
    # crashed inside drift observation, so neon-relay-v3 carries the identical
    # mission on a third run identity.  The ACP client-authority repair extends
    # it once more: v3's attempt is durably consumed by the run whose client
    # granted allow_always and then died on cursor/update_todos, so neon-relay-v4
    # carries the identical mission on a fourth run identity.
    assert set(profiles) == set(LEGACY_FINGERPRINTS) | {
        EXPECTED_PROFILE_ID, "neon-relay-v2", "neon-relay-v3", "neon-relay-v4",
    }
    v2 = resolve_registered_profile("neon-relay-v2")
    assert v2.profile_fingerprint == (
        "3dd4ce6198e450b420afab4ed1e19acfcb7e807e292d87cafdc475ad0ca2c3b6"
    )
    assert v2.profile_fingerprint != PROFILE.profile_fingerprint
    assert v2.mission_text == PROFILE.mission_text
    assert v2.verifier_source_sha256 == PROFILE.verifier_source_sha256
    v3 = resolve_registered_profile("neon-relay-v3")
    assert v3.profile_fingerprint == (
        "d871015d5a0ca8fc1ed050264a5c30845162cce8396fae6fa5fa2f0352253ec6"
    )
    assert len({v3.profile_fingerprint, v2.profile_fingerprint, PROFILE.profile_fingerprint}) == 3
    assert v3.mission_text == PROFILE.mission_text
    assert v3.verifier_source_sha256 == PROFILE.verifier_source_sha256
    v4 = resolve_registered_profile("neon-relay-v4")
    assert v4.profile_fingerprint == (
        "6380e810995b6cd97db408fe4f434328890dafd48d0f5a7468eca010fa8fc97a"
    )
    assert len({
        v4.profile_fingerprint, v3.profile_fingerprint, v2.profile_fingerprint,
        PROFILE.profile_fingerprint,
    }) == 4
    assert v4.mission_text == PROFILE.mission_text
    assert v4.verifier_source_sha256 == PROFILE.verifier_source_sha256
    with pytest.raises(ValueError, match="unknown mission profile"):
        resolve_registered_profile("neon-relay-v5")


def test_neon_siege_definition_remains_unchanged():
    assert NEON_SIEGE_PROFILE.profile_fingerprint == EXPECTED_NEON_SIEGE_FINGERPRINT
    assert NEON_SIEGE_PROFILE.profile_id == "neon-siege-v1"
    assert NEON_SIEGE_PROFILE.schema_version == "admissible_native_mission_profile_v1"
    assert NEON_SIEGE_PROFILE.required_commit_message == (
        "feat: build deployable Neon Siege browser game"
    )
    assert NEON_SIEGE_PROFILE.required_material_paths == ("README.md", "index.html", "package.json")
    assert NEON_SIEGE_PROFILE.timeout_seconds == 3600
    assert NEON_SIEGE_PROFILE.effective_workspace_source.kind is WorkspaceSourceKind.REGISTERED_FIXTURE
    assert NEON_SIEGE_PROFILE.verifier_source != NEON_RELAY_VERIFIER_SOURCE


def _neon_relay_evaluation_variant(schema_version: str) -> NativeMissionProfile:
    """Build the V3/V4/V5 post-run evaluation shape over the same runtime body."""

    values = {
        key: value
        for key, value in PROFILE.__dict__.items()
        if key
        not in {
            "schema_version",
            "profile_fingerprint",
            "fixture_id",
            "fixture_version",
            "required_commit_message",
            "required_material_paths",
            "verifier_source",
            "verifier_source_sha256",
            "verifier_timeout_seconds",
            "verifier_output_limit_bytes",
            "fixture_initial_commit_message",
            "claim_authority",
            "claim_verification_plan_authority",
            "verification_evidence_binding_authority",
        }
    }
    claim_authority = ClaimAuthority(
        authorship=ClaimAuthorship.OWNER_AUTHORED,
        coverage_status=ClaimSetCoverageStatus.NOT_ASSESSED,
        claims=(
            ResultClaim(
                "neon-relay.claim.checkpoint",
                "The public npm-test checkpoint exited zero.",
                ClaimObligationLevel.MANDATORY,
                (),
                ("This does not establish playability or visual quality.",),
            ),
        ),
    )
    if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3:
        return create_native_mission_profile(
            **values, schema_version=schema_version, claim_authority=claim_authority
        )
    obligation = VerificationObligation(
        obligation_id="neon-relay.verify.checkpoint",
        claim_ids=("neon-relay.claim.checkpoint",),
        strategy=VerificationStrategy.CHECKPOINT_COMMAND,
        procedure_reference="npm-test",
        acceptance_predicate=VerificationAcceptancePredicate.EXIT_CODE_ZERO,
        declared_coverage="Exercises the authorized bounded checkpoint only.",
        non_claims=(
            "Does not establish complete mission coverage.",
            "Does not adjudicate visual quality.",
        ),
        oracle_disclosed_to_subject=False,
        independence_requirements=VerificationIndependenceRequirements(
            temporal=True,
            artifact=True,
            process=True,
            information=False,
            model=True,
            organizational=True,
        ),
        negative_controls=(
            VerificationNegativeControl("neon-relay.negative.one", "A failing suite is rejected."),
            VerificationNegativeControl("neon-relay.negative.two", "An absent suite is rejected."),
        ),
        reference_cases=("neon-relay.case.one", "neon-relay.case.two"),
    )
    plan = ClaimVerificationPlanAuthority(
        VerificationPlanAuthorship.OWNER_AUTHORED,
        VerificationPlanCoverageStatus.NOT_ASSESSED,
        (obligation,),
    )
    if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4:
        return create_native_mission_profile(
            **values,
            schema_version=schema_version,
            claim_authority=claim_authority,
            claim_verification_plan_authority=plan,
        )
    bindings = VerificationEvidenceBindingAuthority(
        VerificationEvidenceBindingAuthorship.OWNER_AUTHORED,
        VerificationEvidenceBindingCoverageStatus.NOT_ASSESSED,
        (
            VerificationEvidenceBinding(
                binding_id="neon-relay.binding.one",
                obligation_id="neon-relay.verify.checkpoint",
                source_authority_type=(
                    VerificationEvidenceSourceAuthorityType.CHECKPOINT_COMMAND_AUTHORITY
                ),
                source_authority_reference="npm-test",
            ),
        ),
    )
    return create_native_mission_profile(
        **values,
        schema_version=schema_version,
        claim_authority=claim_authority,
        claim_verification_plan_authority=plan,
        verification_evidence_binding_authority=bindings,
    )


@pytest.mark.parametrize(
    "schema_version",
    [
        MISSION_PROFILE_SCHEMA_VERSION_V3,
        MISSION_PROFILE_SCHEMA_VERSION_V4,
        MISSION_PROFILE_SCHEMA_VERSION_V5,
    ],
)
def test_historical_pairing_evaluation_schemas_remain_non_launchable(
    schema_version: str, tmp_path: Path
):
    evaluation = _neon_relay_evaluation_variant(schema_version)
    assert evaluation.schema_version == schema_version
    assert evaluation.has_nested_runtime_authority is True
    assert evaluation.is_launchable_runtime_profile is False
    assert evaluation.profile_fingerprint != EXPECTED_PROFILE_FINGERPRINT
    with pytest.raises(ValueError, match="launchable runtime-v2 schema"):
        create_canary_session(session_id=PROFILE.session_id, profile=evaluation)
    document = tmp_path / f"{schema_version}.json"
    document.write_bytes(canonical_bytes(evaluation.to_dict()) + b"\n")
    with pytest.raises(ValueError, match="must use the v2 schema"):
        load_native_mission_profile_document(document.resolve())
    assert schema_version not in {
        profile.schema_version for profile in registered_profiles().values()
    }


# ---------------------------------------------------------------------------
# Frozen verifier: clean control, blank control, twenty mutations.
# ---------------------------------------------------------------------------


def test_frozen_verifier_passes_the_known_good_conformance_fixture(tmp_path: Path):
    workspace = _materialize(tmp_path / "work", CONFORMANCE_FILES)
    script = _write_verifier(tmp_path)
    report = _report(_execute(script, workspace))
    assert report["failedClauses"] == []
    assert report["ok"] is True
    assert report["_exit_code"] == 0
    assert report["_success_line"] is True
    assert report["_stderr"] == ""
    assert report["verifier"] == "neon-relay-v1"
    assert report["clauseCount"] == 18
    assert [entry["id"] for entry in report["clauses"]] == list(NEON_RELAY_VERIFIER_CLAUSE_IDS)
    assert all(entry["ok"] for entry in report["clauses"])
    assert all(entry["message"] for entry in report["clauses"])
    assert report["nonClaims"] == list(NEON_RELAY_VERIFIER_NON_CLAIMS)
    assert report["_stdout_bytes"] <= NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES
    assert "truncated" not in report


def test_frozen_verifier_refuses_the_actual_blank_fixture(tmp_path: Path):
    fixture = Path(EXPECTED_FIXTURE_PATH)
    assert fixture.is_dir()
    before = _observe_local_repository_source(fixture)
    script = _write_verifier(tmp_path)
    report = _report(_execute(script, fixture))
    assert report["ok"] is False
    assert report["_exit_code"] == 1
    assert report["_success_line"] is False
    assert report["failedClauses"] == list(NEON_RELAY_VERIFIER_CLAUSE_IDS)
    assert report["_stdout_bytes"] <= NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES
    messages = {entry["id"]: entry["message"] for entry in report["clauses"]}
    assert "required regular files are missing" in messages["C01_required_paths"]
    for required in ("index.html", "src/game.js", "test/game.test.js", "style.css"):
        assert required in messages["C01_required_paths"]
    assert "node --test" in messages["C02_package_contract"]
    assert "fixture marker present" in messages["C03_no_external_runtime"]
    for clause_id in ("C04_domain_is_pure", "C05_agent_tests_are_behavioural"):
        assert "src" in messages[clause_id] or "test" in messages[clause_id]
    assert "not importable" in messages["C06_domain_surface_importable"]
    for clause_id in NEON_RELAY_VERIFIER_CLAUSE_IDS[6:]:
        assert "domain surface is unavailable" in messages[clause_id]
    # Reading the blank fixture mutates nothing.
    assert _observe_local_repository_source(fixture) == before


def test_every_mutation_is_distinct_and_targets_a_known_clause():
    assert len(MUTATIONS) == 20
    assert len({mutation.mutation_id for mutation in MUTATIONS}) == 20
    assert len({mutation.description for mutation in MUTATIONS}) == 20
    for mutation in MUTATIONS:
        assert mutation.intended_clause in NEON_RELAY_VERIFIER_CLAUSE_IDS
        if not mutation.mutates_verifier and not mutation.delete_path:
            assert mutation.path in CONFORMANCE_FILES
    assert {mutation.intended_clause for mutation in MUTATIONS} >= set(
        NEON_RELAY_VERIFIER_CLAUSE_IDS
    ) - {"C06_domain_surface_importable", "C07_seeded_determinism"}


@pytest.mark.parametrize("mutation", MUTATIONS, ids=lambda item: item.mutation_id)
def test_frozen_verifier_kills_every_clause_mutation(mutation: Mutation, tmp_path: Path):
    workspace = _materialize(tmp_path / "work", CONFORMANCE_FILES)
    if mutation.base_mutation is not None:
        base = next(item for item in MUTATIONS if item.mutation_id == mutation.base_mutation)
        _apply_mutation(workspace, base)
    if mutation.mutates_verifier:
        assert NEON_RELAY_VERIFIER_SOURCE.count(mutation.old) == 1
        mutated = NEON_RELAY_VERIFIER_SOURCE.replace(mutation.old, mutation.new)
        assert mutated != NEON_RELAY_VERIFIER_SOURCE
        script = _write_verifier(tmp_path, mutated)
        check = subprocess.run(
            [_node(), "--check", str(script)], capture_output=True, text=True, check=False, timeout=60
        )
        assert check.returncode == 0, f"mutant verifier must parse: {check.stderr[:500]}"
        report = _report(_execute(script, workspace))
        # The mutant proves the success gate is load-bearing: it emits the
        # success line and exit zero although a clause failed, which is exactly
        # what the committed gating assertion below refuses.
        assert mutation.intended_clause in report["failedClauses"]
        assert report["_success_line"] is True
        assert report["_exit_code"] == 0
        return
    _apply_mutation(workspace, mutation)
    script = _write_verifier(tmp_path)
    report = _report(_execute(script, workspace))
    assert report["_stderr"] == "", f"mutant must execute normally: {report['_stderr'][:500]}"
    assert report["clauseCount"] == 18, "the mutant must run every clause, not abort collection"
    assert mutation.intended_clause in report["failedClauses"], (
        f"{mutation.mutation_id} survived {mutation.intended_clause}: "
        f"failed={report['failedClauses']}"
    )
    assert report["ok"] is False
    assert report["_exit_code"] == 1
    assert report["_success_line"] is False


def test_frozen_verifier_gates_its_success_line_on_every_clause(tmp_path: Path):
    """The gating law that mutation MUT-20 violates."""

    workspace = _materialize(tmp_path / "work", CONFORMANCE_FILES)
    (workspace / "style.css").unlink()
    script = _write_verifier(tmp_path)
    report = _report(_execute(script, workspace))
    assert report["failedClauses"] == ["C01_required_paths"]
    assert report["ok"] is False
    assert report["_success_line"] is False
    assert report["_exit_code"] == 1
