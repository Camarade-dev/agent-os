"""Neon Siege v1 exact prompt, completion conditions, and behavioral verifier.

Canonical comparison-experiment text authorities. The fingerprinted
``NativeMissionProfile`` is assembled in :mod:`mission_profile` so imports stay
acyclic with the shared profile constructor.
"""

from __future__ import annotations

import hashlib


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# Exact UTF-8 user prompt for the Neon Siege comparison experiment.
# Locked length 2739; SHA-256 5a4ad58e5aef0309bcd347b209682c5273738fabcfed959e6b19c6b3a3aefd30.
NEON_SIEGE_EXACT_USER_PROMPT = (
    "Build a complete, visually polished browser game called **Neon Siege** in the current workspace.\n"
    "\n"
    "Neon Siege should be a top-down neon arena survival game that is immediately playable, satisfying, "
    "and visually impressive enough to record in a product demonstration.\n"
    "\n"
    "Use only plain HTML, CSS, and JavaScript. Do not use frameworks, CDNs, external APIs, downloaded "
    "assets, or runtime network dependencies. The finished project must be deployable as a static website "
    "on services such as GitHub Pages, Netlify, or Vercel.\n"
    "\n"
    "The game should include:\n"
    "\n"
    "* a polished title screen with clear controls and a Play button;\n"
    "* player movement using WASD or the arrow keys;\n"
    "* mouse aiming and shooting;\n"
    "* a dash ability with a visible cooldown;\n"
    "* increasingly difficult enemy waves;\n"
    "* at least three enemy archetypes with meaningfully different behavior;\n"
    "* player health, damage, death, and a health recovery mechanic;\n"
    "* score, current wave, health, and dash status in the HUD;\n"
    "* pause and resume;\n"
    "* a between-wave upgrade system offering three choices;\n"
    "* upgrades with visible gameplay effects and multiple levels;\n"
    "* a game-over screen showing the final score and wave reached;\n"
    "* a complete restart flow;\n"
    "* a persistent local high score using localStorage;\n"
    "* locally generated audio feedback using the Web Audio API, with a mute control;\n"
    "* strong visual feedback such as particles, impact flashes, trails, screen shake, animated "
    "backgrounds, or equivalent polish;\n"
    "* responsive behavior on ordinary desktop browser sizes.\n"
    "\n"
    "Organize the code clearly and separate important game-state logic from rendering where reasonable. "
    "Include meaningful automated tests for core game logic using Node\u2019s built-in test runner without "
    "external test libraries.\n"
    "\n"
    "Provide dependency-free `npm test` and `npm start` commands. The start command must serve the project "
    "locally without requiring a globally installed third-party package.\n"
    "\n"
    "Include a concise README explaining how to run, test, and later deploy the game.\n"
    "\n"
    "Work autonomously and make reasonable product decisions without asking routine questions. Inspect and "
    "verify the complete project before declaring completion. Run the tests, start the application locally, "
    "and fix any problems you discover.\n"
    "\n"
    "Do not add a Git remote, push, publish, or perform a real deployment.\n"
    "\n"
    "Stop only when the game is complete and working end-to-end, the tests pass, the local start command "
    "works, and exactly one final Git commit has been created with the message:\n"
    "\n"
    "`feat: build deployable Neon Siege browser game`\n"
    "\n"
    "At the end, report the implemented features, files changed, verification performed, known limitations, "
    "and exact final commit hash. Do not claim success unless the stated completion conditions are actually "
    "satisfied."
)

NEON_SIEGE_EXACT_USER_PROMPT_BYTE_LENGTH = 2739
NEON_SIEGE_EXACT_USER_PROMPT_SHA256 = (
    "5a4ad58e5aef0309bcd347b209682c5273738fabcfed959e6b19c6b3a3aefd30"
)

NEON_SIEGE_REQUIRED_COMMIT_MESSAGE = "feat: build deployable Neon Siege browser game"

NEON_SIEGE_REQUIRED_MATERIAL_PATHS = (
    "README.md",
    "index.html",
    "package.json",
)

NEON_SIEGE_COMPLETION_CONDITIONS_TEXT = f"""Required completion conditions:
- satisfy every mission requirement and gate clause without adding game features
  beyond those already stated in the immutable mission text;

- run the complete `npm test` suite and require it to pass;

- confirm that each hard material path below is created or materially modified
  in the task commit:

  - README.md
  - index.html
  - package.json

- ensure the final tree also contains at least one non-test JavaScript source
  file and at least one automated test file; filenames are otherwise free;

- keep `package.json` free of runtime and test package dependencies, and keep
  `npm test` / `npm start` dependency-free;

- create exactly one intended local task commit after the fixture baseline with
  the exact complete message `{NEON_SIEGE_REQUIRED_COMMIT_MESSAGE}`;

- use no `--trailer` when creating or amending the commit;

- add no commit-message body, `Co-authored-by`, sign-off, attribution or other
  trailer;

- before stopping, run `git log -1 --format=%B` and verify that its complete
  output, after removing terminal newline characters only, is exactly
  `{NEON_SIEGE_REQUIRED_COMMIT_MESSAGE}`;

- if the complete message is not exact, amend that same task commit during this
  native invocation, do not create a second task commit, and run the exact
  `%B` verification again;

- confirm the worktree and index are clean;

- confirm no Git remotes exist;

- do not amend, replace or recreate the fixture baseline commit;

- do not read or modify the source repository, sibling run roots, sibling
  workspaces, evidence directories, authorization records or prior-run
  artifacts;

- do not install dependencies, access the network for runtime assets, add a
  remote, push or deploy;

- expose at least one Node-importable ES module that exports `createGameState`
  so the independent behavioral verifier can exercise start/play, pause,
  resume, game-over, restart, waves, upgrades with multiple levels, health or
  damage, score, high-score persistence through injectable storage, dash
  cooldown, and `listEnemyTypes()` with at least three distinguishable
  archetypes without requiring a browser; the module path is otherwise free;

- honor `HOST` and `PORT` for `npm start` (defaults `127.0.0.1` and `8765`) so
  the independent bounded local-start probe can confirm the static app serves
  and then terminate the exact server process tree;

- do not continue with optional polish after the final verification.

Independent behavioral verification does not establish subjective visual polish
or complete human playability; those require later human review of the locally
served result.

Stop immediately only after the complete npm test suite passes, every required
material path is present in the single intended task commit, the exact complete
commit message has been verified with `git log -1 --format=%B`, the worktree
and index are clean, and the repository has zero remotes. Do not perform
further exploration or changes after those checks."""

# Independent, non-generative verifier. Discovers createGameState, exercises
# lifecycle/combat seams, checks static deployability, and bounds npm start.
NEON_SIEGE_VERIFIER_SOURCE = r"""import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readdir, readFile, access } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { dirname, join, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = process.argv[2];
assert.ok(root && typeof root === 'string', 'workspace root argument is required');

const PROBE_HOST = process.env.HOST || '127.0.0.1';
const PROBE_PORT = Number(process.env.PORT || 8765);
const START_TIMEOUT_MS = 20_000;
const REQUEST_TIMEOUT_MS = 5_000;
const FORBIDDEN_NET = [
  /cdn\./i,
  /unpkg\.com/i,
  /jsdelivr/i,
  /googleapis\.com/i,
  /google-analytics/i,
  /cdnjs\.cloudflare\.com/i,
  /https?:\/\/(?!127\.0\.0\.1|localhost\b)[a-z0-9.-]+\.[a-z]{2,}/i,
];
const PLACEHOLDER = /\bTODO\b|\bFIXME\b|not implemented|throw new Error\(['"]not implemented/i;

function posix(relativePath) {
  return relativePath.split(sep).join('/');
}

async function exists(relativePath) {
  try {
    await access(join(root, relativePath));
    return true;
  } catch {
    return false;
  }
}

async function walk(dir, acc = []) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, acc);
    else if (entry.isFile()) acc.push(full);
  }
  return acc;
}

function isTestPath(rel) {
  return /(^|\/)test\//.test(rel) || /\.test\.(m?js)$/.test(rel) || /(^|\/)tests\//.test(rel);
}

function memoryStorage(seed = {}) {
  const values = new Map(Object.entries(seed).map(([k, v]) => [String(k), String(v)]));
  return {
    getItem(key) { return values.has(String(key)) ? values.get(String(key)) : null; },
    setItem(key, value) { values.set(String(key), String(value)); },
    removeItem(key) { values.delete(String(key)); },
    clear() { values.clear(); },
  };
}

function portFree(port, host) {
  return new Promise((resolve) => {
    const socket = createConnection({ port, host });
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => resolve(true));
  });
}

async function waitForPort(port, host, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (!(await portFree(port, host))) return;
    await delay(100);
  }
  throw new Error(`local start did not open ${host}:${port} within ${timeoutMs}ms`);
}

async function httpGet(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, { signal: controller.signal });
    const text = await response.text();
    return { status: response.status, text };
  } finally {
    clearTimeout(timer);
  }
}

async function killProcessTree(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    await new Promise((resolve) => {
      const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      });
      killer.once('exit', resolve);
      killer.once('error', resolve);
    });
  } else {
    try { process.kill(child.pid, 'SIGKILL'); } catch { /* already gone */ }
  }
  await delay(200);
}

async function boundedLocalStartProbe() {
  assert.equal(await portFree(PROBE_PORT, PROBE_HOST), true, `probe port ${PROBE_PORT} must be free before start`);
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const child = spawn(npmCmd, ['start'], {
    cwd: root,
    env: { ...process.env, HOST: PROBE_HOST, PORT: String(PROBE_PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    shell: process.platform === 'win32',
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  let exitCode = null;
  child.on('exit', (code) => { exitCode = code; });
  try {
    await waitForPort(PROBE_PORT, PROBE_HOST, START_TIMEOUT_MS);
    const page = await httpGet(`http://${PROBE_HOST}:${PROBE_PORT}/`);
    assert.equal(page.status, 200, 'npm start must serve HTTP 200 for /');
    assert.match(page.text, /Neon Siege|canvas|neon-siege/i, 'served document must look like the game page');
    assert.ok(!(await exists('node_modules')), 'start must remain dependency-free (no node_modules)');
  } catch (error) {
    await killProcessTree(child);
    const detail = `${error}\nstdout:\n${stdout}\nstderr:\n${stderr}\nexit:${exitCode}`;
    throw new Error(`bounded local-start probe failed: ${detail}`);
  }
  await killProcessTree(child);
  const free = await portFree(PROBE_PORT, PROBE_HOST);
  assert.equal(free, true, 'local start probe must leave no listener behind');
  return { host: PROBE_HOST, port: PROBE_PORT, stdoutBytes: Buffer.byteLength(stdout), stderrBytes: Buffer.byteLength(stderr) };
}

// 1. Required anchors and package contract.
for (const relativePath of ['README.md', 'index.html', 'package.json']) {
  assert.equal(await exists(relativePath), true, `missing required path: ${relativePath}`);
}
const packageJson = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
assert.equal(typeof packageJson.scripts?.test, 'string', 'package.json must expose npm test');
assert.equal(typeof packageJson.scripts?.start, 'string', 'package.json must expose npm start');
assert.ok(!packageJson.scripts.test.includes('npx '), 'npm test must not use npx');
assert.ok(!packageJson.scripts.start.includes('npx '), 'npm start must not use npx');
for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
  const value = packageJson[field];
  if (value == null) continue;
  assert.equal(Object.keys(value).length, 0, `${field} must be empty for dependency-free delivery`);
}

const files = await walk(root);
const relFiles = files.map((full) => posix(relative(root, full)));
const jsSources = relFiles.filter((rel) => /\.m?js$/.test(rel) && !isTestPath(rel));
const testFiles = relFiles.filter((rel) => isTestPath(rel) && /\.m?js$/.test(rel));
assert.ok(jsSources.length >= 1, 'at least one non-test JavaScript source file is required');
assert.ok(testFiles.length >= 1, 'at least one automated test file is required');
const readmeText = await readFile(join(root, 'README.md'), 'utf8');
assert.doesNotMatch(readmeText, /NEON_SIEGE_BLANK_FIXTURE_V1/, 'blank fixture marker must not remain in README');

// 2. Forbidden external runtime references and obvious placeholders.
const textFiles = relFiles.filter((rel) => /\.(html|css|m?js|md|json)$/i.test(rel));
let combined = '';
for (const rel of textFiles) {
  const text = await readFile(join(root, rel), 'utf8');
  combined += `\n${text}`;
  if (/\.(html|css|m?js)$/i.test(rel)) {
    for (const pattern of FORBIDDEN_NET) {
      if (pattern.test(text)) {
        // Allow pure documentation mentions in README only.
        assert.ok(false, `forbidden external runtime reference in ${rel}: ${pattern}`);
      }
    }
  }
}
assert.doesNotMatch(combined, PLACEHOLDER);

// 3. index.html must be statically self-contained enough to deploy.
const indexHtml = await readFile(join(root, 'index.html'), 'utf8');
assert.doesNotMatch(indexHtml, /<script[^>]+src=["']https?:/i);
assert.doesNotMatch(indexHtml, /<link[^>]+href=["']https?:/i);
assert.match(indexHtml, /<script/i);
assert.match(indexHtml, /Neon Siege|neon-siege|canvas/i);

// 4. Source must contain implemented lifecycle and combat vocabulary.
for (const token of [
  'pause', 'resume', 'restart', 'wave', 'upgrade', 'dash', 'score', 'health',
  'highScore', 'localStorage', 'AudioContext', 'mute',
]) {
  assert.match(combined, new RegExp(token, 'i'), `source/tests must implement or cover ${token}`);
}

// 5. Automated tests must assert core state, not only file existence.
let testText = '';
for (const rel of testFiles) testText += `\n${await readFile(join(root, rel), 'utf8')}`;
assert.match(testText, /\bassert\b|\bstrictEqual\b|\bdeepEqual\b|\bequal\b/, 'tests must contain assertions');
assert.doesNotMatch(testText.trim(), /^[\s\S]*existsSync[\s\S]*$/);
for (const token of ['wave', 'upgrade', 'restart', 'dash', 'score', 'health']) {
  assert.match(testText, new RegExp(token, 'i'), `tests must cover ${token}`);
}
assert.ok(!/NEON_SIEGE_BLANK_FIXTURE_V1/.test(testText) || testFiles.length > 1,
  'fixture-only identity tests are insufficient without game-logic tests');

// 6. Discover and exercise createGameState.
const candidates = [];
for (const rel of jsSources) {
  const sourceText = await readFile(join(root, rel), 'utf8');
  if (!sourceText.includes('createGameState')) continue;
  try {
    const mod = await import(pathToFileURL(join(root, rel)).href);
    if (typeof mod.createGameState === 'function') candidates.push({ rel, mod });
  } catch (error) {
    throw new Error(`createGameState module failed to import (${rel}): ${error}`);
  }
}
assert.ok(candidates.length >= 1, 'no Node-importable createGameState export was discovered');

const storage = memoryStorage();
const { createGameState } = candidates[0].mod;
const game = createGameState({ storage });
assert.equal(typeof game, 'object', 'createGameState must return an object');
for (const method of ['start', 'pause', 'resume', 'restart']) {
  assert.equal(typeof game[method], 'function', `createGameState().${method} must be a function`);
}

const started = game.start();
const startedState = started && typeof started === 'object' ? started : game.getState?.() ?? game.state ?? game;
assert.ok(startedState, 'start must yield inspectable state');
const readState = () => {
  if (typeof game.getState === 'function') return game.getState();
  if (game.state && typeof game.state === 'object') return game.state;
  return game;
};
let state = readState();
const phaseOf = (value) => String(value.phase ?? value.status ?? value.screen ?? value.mode ?? '').toLowerCase();
assert.match(phaseOf(state), /play|running|active|game/, 'start must enter a playable phase');

game.pause();
state = readState();
assert.match(phaseOf(state), /pause/, 'pause must enter a paused phase');
game.resume();
state = readState();
assert.match(phaseOf(state), /play|running|active|game/, 'resume must leave paused phase');

assert.ok(
  typeof game.applyDamage === 'function' || typeof game.damagePlayer === 'function' || typeof game.hitPlayer === 'function',
  'health/damage seam is required',
);
const damage = game.applyDamage || game.damagePlayer || game.hitPlayer;
const beforeHealth = Number(readState().health ?? readState().player?.health);
damage.call(game, Math.max(1, Math.floor(beforeHealth / 2) || 1));
const afterHealth = Number(readState().health ?? readState().player?.health);
assert.ok(afterHealth < beforeHealth, 'damage must reduce health');

assert.ok(typeof game.activateDash === 'function' || typeof game.dash === 'function', 'dash seam is required');
const dash = game.activateDash || game.dash;
dash.call(game);
state = readState();
const dashStatus = state.dash ?? state.dashCooldown ?? state.player?.dashCooldown;
assert.ok(dashStatus !== undefined && dashStatus !== null, 'dash must expose cooldown/status');

assert.ok(
  typeof game.offerUpgrades === 'function' || typeof game.getUpgradeChoices === 'function' || typeof game.beginUpgradeSelection === 'function',
  'upgrade choice seam is required',
);
const offer = game.offerUpgrades || game.getUpgradeChoices || game.beginUpgradeSelection;
const choices = offer.call(game) || readState().upgradeChoices || readState().upgrades;
assert.ok(Array.isArray(choices) && choices.length === 3, 'upgrade system must offer three choices');
assert.ok(typeof game.applyUpgrade === 'function' || typeof game.selectUpgrade === 'function', 'upgrade apply seam is required');
const applyUpgrade = game.applyUpgrade || game.selectUpgrade;
const choice = choices[0];
const choiceId = choice.id ?? choice.key ?? choice.name ?? choice;
applyUpgrade.call(game, choiceId);
applyUpgrade.call(game, choiceId);
state = readState();
const levels = state.upgradeLevels ?? state.upgrades ?? state.player?.upgrades;
assert.ok(levels, 'upgrades must expose levels after repeated application');

assert.ok(
  typeof game.advanceWave === 'function' || typeof game.nextWave === 'function' || typeof game.spawnWave === 'function',
  'wave progression seam is required',
);
const waveFn = game.advanceWave || game.nextWave || game.spawnWave;
const waveBefore = Number(readState().wave ?? readState().currentWave ?? 0);
waveFn.call(game);
const waveAfter = Number(readState().wave ?? readState().currentWave ?? 0);
assert.ok(waveAfter > waveBefore, 'wave progression must increase the wave counter');

assert.ok(
  typeof game.addScore === 'function' || typeof game.scoreKill === 'function' || typeof game.registerScore === 'function',
  'score seam is required',
);
const scoreFn = game.addScore || game.scoreKill || game.registerScore;
scoreFn.call(game, 25);
assert.ok(Number(readState().score ?? 0) >= 25, 'score must increase');

assert.ok(typeof game.triggerGameOver === 'function' || typeof game.gameOver === 'function', 'game-over seam is required');
const over = game.triggerGameOver || game.gameOver;
over.call(game);
state = readState();
assert.match(phaseOf(state), /over|gameover|defeat|dead/, 'game over must enter a terminal phase');
const high = state.highScore ?? storage.getItem('neon-siege-high-score') ?? storage.getItem('highScore');
assert.ok(high !== null && high !== undefined, 'high score must persist through injectable storage or state');

game.restart();
state = readState();
assert.match(phaseOf(state), /title|menu|ready|play|running|active|game/, 'restart must leave game-over');
assert.equal(Number(state.score ?? 0), 0, 'restart must reset score');

// Enemy archetypes must be distinguishable in executable source or returned state.
assert.ok(typeof game.listEnemyTypes === 'function', 'listEnemyTypes seam is required for archetype proof');
const enemyTypes = game.listEnemyTypes();
assert.ok(Array.isArray(enemyTypes) && enemyTypes.length >= 3, 'listEnemyTypes must expose >= 3 archetypes');
const behaviors = new Set(enemyTypes.map((entry) => entry.behavior || entry.ai || entry.kind || entry.id || entry));
assert.ok(behaviors.size >= 3, 'enemy archetypes must differ by behavior identity');
assert.match(combined, /chaser|tank|dasher|shooter|orbiter|swarm|sniper|brute|runner|drone/i);

// 7. Bounded local-start probe with mandatory cleanup.
const probe = await boundedLocalStartProbe();

console.log(JSON.stringify({
  ok: true,
  verifier: 'neon-siege-v1',
  createGameStateModule: candidates[0].rel,
  localStart: probe,
  nonClaims: [
    'subjective visual polish was not independently established',
    'complete human playability was not independently established',
  ],
}));
console.log('neon-siege behavioral verifier passed');
"""

assert _sha256_text(NEON_SIEGE_EXACT_USER_PROMPT) == NEON_SIEGE_EXACT_USER_PROMPT_SHA256
assert len(NEON_SIEGE_EXACT_USER_PROMPT.encode("utf-8")) == NEON_SIEGE_EXACT_USER_PROMPT_BYTE_LENGTH

NEON_SIEGE_VERIFIER_SOURCE_SHA256 = _sha256_text(NEON_SIEGE_VERIFIER_SOURCE)


__all__ = [
    "NEON_SIEGE_COMPLETION_CONDITIONS_TEXT",
    "NEON_SIEGE_EXACT_USER_PROMPT",
    "NEON_SIEGE_EXACT_USER_PROMPT_BYTE_LENGTH",
    "NEON_SIEGE_EXACT_USER_PROMPT_SHA256",
    "NEON_SIEGE_REQUIRED_COMMIT_MESSAGE",
    "NEON_SIEGE_REQUIRED_MATERIAL_PATHS",
    "NEON_SIEGE_VERIFIER_SOURCE",
    "NEON_SIEGE_VERIFIER_SOURCE_SHA256",
]
