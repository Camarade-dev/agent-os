"""Neon Relay v1 exact mission text, completion conditions, and frozen verifier.

Canonical text authorities for the ``neon-relay-v1`` native mission.  The
fingerprinted :class:`~admissible.delegated_gate.mission_profile.NativeMissionProfile`
is assembled in :mod:`mission_profile` so imports stay acyclic with the shared
profile constructor.

Nothing in this module reaches a provider, a browser, a socket, or a
subprocess.  The verifier source below is frozen text: it is hashed here,
disclosed to the provider through the profile, and executed later by the
unchanged native behavioral-verifier path with the delivered workspace root as
its sole positional argument.
"""

from __future__ import annotations

import hashlib


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


NEON_RELAY_REQUIRED_COMMIT_MESSAGE = "feat: build playable Neon Relay browser game"

NEON_RELAY_FIXTURE_MARKER = "NEON_RELAY_BLANK_FIXTURE_V1"

# Exact ordered required material set.  Every path must be created or
# materially changed between the fixture initial commit and the task commit.
NEON_RELAY_REQUIRED_MATERIAL_PATHS = (
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

NEON_RELAY_DOMAIN_MODULE_PATHS = (
    "src/random.js",
    "src/state-machine.js",
    "src/entities.js",
    "src/combat.js",
    "src/upgrades.js",
    "src/game.js",
)

NEON_RELAY_STATES = (
    "TITLE",
    "RUNNING",
    "PAUSED",
    "UPGRADE",
    "GAME_OVER",
    "VICTORY",
)

NEON_RELAY_ENEMY_TYPES = ("chaser", "shooter", "splitter")

NEON_RELAY_OPERATIONS = (
    "start",
    "pause",
    "resume",
    "advance",
    "restart",
    "dash",
    "spawnEnemy",
    "damageEnemy",
    "damagePlayer",
    "enterRelayZone",
    "leaveRelayZone",
    "removeEnemy",
    "completeRelay",
    "availableUpgrades",
    "applyUpgrade",
    "damageBoss",
    "listEnemyTypes",
    "getEvents",
    "getState",
)

NEON_RELAY_VERIFIER_CLAUSE_IDS = (
    "C01_required_paths",
    "C02_package_contract",
    "C03_no_external_runtime",
    "C04_domain_is_pure",
    "C05_agent_tests_are_behavioural",
    "C06_domain_surface_importable",
    "C07_seeded_determinism",
    "C08_paused_does_not_progress",
    "C09_restart_resets",
    "C10_legal_transitions",
    "C11_dash_cooldown_bounded",
    "C12_upgrade_applied_once",
    "C13_splitter_divides_once",
    "C14_relay_contesting_law",
    "C15_game_over_stops_simulation",
    "C16_victory_requires_relays_and_boss",
    "C17_entity_bounds",
    "C18_enemy_archetypes",
)

NEON_RELAY_VERIFIER_NON_CLAIMS = (
    "subjective visual quality was not independently established",
    "control feel and complete human playability were not independently established",
    "no browser was launched and rendering was not observed",
    "no server was started and no network access was attempted",
)

NEON_RELAY_VERIFIER_SUCCESS_LINE = "neon-relay behavioral verifier passed"


# ---------------------------------------------------------------------------
# Provider-facing mission text.
# ---------------------------------------------------------------------------

NEON_RELAY_MISSION_TEXT = """Build a complete, browser-playable 2D game called Neon Relay in the assigned
workspace.

Technology constraints
- plain HTML, plain CSS and JavaScript ES modules only;
- automated tests use the Node built-in test runner (`node --test`) only;
- zero production dependencies and zero development dependencies;
- zero CDN, zero external asset, zero network requirement;
- the game must run entirely from local files with no server and no build step.

Controls
- WASD moves the player;
- the mouse aims;
- the primary mouse button fires;
- Space performs a dash;
- P pauses and resumes;
- R restarts from GAME_OVER or VICTORY.

Exact domain states
The domain has exactly these six states, named exactly:
TITLE, RUNNING, PAUSED, UPGRADE, GAME_OVER, VICTORY.

Gameplay
- three relay sectors are completed in sequence;
- a relay gains charge only while the player occupies its zone and no living
  enemy contests that zone;
- a contested relay may hold its charge but its charge must never increase;
- charge is bounded above by that relay's fullCharge and below by zero;
- there are exactly three enemy archetypes: chaser, shooter and splitter;
- a generation-zero splitter divides into exactly two generation-one splitters
  when it dies;
- a generation-one splitter never divides;
- player health is bounded between zero and a positive maxHealth;
- the dash has a positive, bounded cooldown;
- after each of the first two relay sectors the run offers exactly three
  distinct upgrade choices;
- exactly one choice can be applied once per offer, and applying it closes that
  offer;
- applied upgrades persist for the remainder of the current run;
- a final boss appears only after the third relay sector is complete;
- victory requires all three relays complete and boss health exactly zero;
- game over requires player health exactly zero;
- the simulation is inert after GAME_OVER and after VICTORY.

Deterministic domain contract
The domain layer is the simulation authority and must be pure and seeded.

`src/random.js` must export:
- `createRandom(seed)` returning an object with a `next()` method that returns a
  finite number in [0, 1). Two generators created with the same seed must yield
  identical sequences; different seeds must yield different sequences.

`src/state-machine.js` must export:
- `STATES`, an object whose keys are exactly the six state names and whose value
  for each key is that key's own name as a string;
- `legalTransitions()` returning an array of two-element `[from, to]` arrays.
  The set of returned pairs must be exactly:
  TITLE->RUNNING, RUNNING->PAUSED, PAUSED->RUNNING, RUNNING->UPGRADE,
  UPGRADE->RUNNING, RUNNING->GAME_OVER, RUNNING->VICTORY, GAME_OVER->TITLE,
  VICTORY->TITLE. No other pair may be returned and no pair may repeat;
- `canTransition(from, to)` returning `true` exactly for those pairs and
  `false` for everything else, including unknown values and self transitions.

`src/game.js` must export:
- `createGame(options)` accepting at least `{ seed }` and returning one game
  object exposing exactly these callable operations:
  start, pause, resume, advance, restart, dash, spawnEnemy, damageEnemy,
  damagePlayer, enterRelayZone, leaveRelayZone, removeEnemy, completeRelay,
  availableUpgrades, applyUpgrade, damageBoss, listEnemyTypes, getEvents,
  getState.

Exact operation contract
- `start()` moves TITLE to RUNNING and is a no-op in every other state.
- `pause()` moves RUNNING to PAUSED and is a no-op elsewhere.
- `resume()` moves PAUSED to RUNNING and is a no-op elsewhere.
- `advance(deltaMs)` is the only operation that advances simulation time. It
  advances only in RUNNING; in every other state it changes nothing at all.
- `restart()` is accepted only from GAME_OVER and VICTORY and returns the domain
  to a snapshot deeply identical to a freshly created game with the same seed,
  with an empty event list.
- `dash()` returns `true` when a dash starts and `false` otherwise. A dash is
  possible only in RUNNING with a zero cooldown. Starting a dash sets
  `dashCooldownMs` to `dashCooldownTotalMs`, which is positive and finite. A
  refused dash must not raise the remaining cooldown.
- `spawnEnemy(type)` spawns exactly one living enemy of that archetype inside
  the currently active relay zone, so it contests that relay until it dies or is
  removed. It returns the created enemy object with a unique `id`, its `type`,
  a positive `health`, a `generation` of 0, and numeric `x` and `y`. It returns
  `null` for an unknown archetype, when the enemy count already equals
  `maxEnemies`, and in every state other than RUNNING.
- `damageEnemy(id, amount)` returns `true` when a living enemy took the damage
  and `false` otherwise, including an unknown id. When a generation-zero
  splitter dies it is replaced by exactly two generation-one splitters.
- `damagePlayer(amount)` reduces health, clamped to zero, never below zero, and
  never heals for a non-positive amount. Reaching zero enters GAME_OVER.
- `enterRelayZone()` and `leaveRelayZone()` set and clear player occupation of
  the active relay zone.
- `removeEnemy(id)` returns `true` when an enemy was removed without dying, so
  it neither divides nor scores, and `false` for an unknown id.
- `completeRelay()` completes the active relay. It returns `true` on success and
  `false` otherwise, including in every state other than RUNNING. Completing the
  first and second relay enters UPGRADE. Completing the third relay activates
  the boss and remains in RUNNING.
- `availableUpgrades()` returns an array of exactly three distinct offer objects
  `{ id, name, description }` while in UPGRADE and an empty array otherwise. An
  offered id must never be an already-applied id.
- `applyUpgrade(id)` returns `true` exactly once per offer, for an offered id,
  while in UPGRADE, and moves the domain back to RUNNING. Every other call
  returns `false` and changes nothing.
- `damageBoss(amount)` returns `true` only while the boss is active and `false`
  otherwise. Boss health is clamped to zero. Boss health zero with all three
  relays complete enters VICTORY.
- `listEnemyTypes()` returns exactly the three archetype ids: chaser, shooter,
  splitter.
- `getEvents()` returns the ordered array of domain events. Every event is an
  object with a string `type` and a numeric `timeMs`.
- `getState()` returns one plain snapshot object containing at least:
  `state`, `timeMs`, `arena` `{ width, height }`,
  `player` `{ health, maxHealth, x, y, dashCooldownMs, dashCooldownTotalMs }`,
  `relays`, an array of exactly three
  `{ index, charge, fullCharge, complete, contested, occupied }`,
  `activeRelayIndex`, `relaysComplete`, `enemies`, an array of
  `{ id, type, health, generation, x, y }`, `maxEnemies` (an integer from 4
  through 128), `projectiles`, `boss` (`null` or
  `{ health, maxHealth, active }`), `appliedUpgrades` and
  `pendingUpgradeChoices` (the three offered ids while in UPGRADE, otherwise
  empty).

Determinism and purity
- the same seed and the same operation sequence must produce deeply identical
  domain events and snapshots;
- an uncontested, occupied relay must reach `fullCharge` after between 3000 and
  60000 milliseconds of accumulated charging time; reaching `fullCharge`
  completes that relay, and a completed relay keeps `charge` equal to
  `fullCharge`;
- the six domain modules `src/random.js`, `src/state-machine.js`,
  `src/entities.js`, `src/combat.js`, `src/upgrades.js` and `src/game.js` must
  never reference `Date.now`, `new Date`, `performance`,
  `requestAnimationFrame`, `document`, `window`, `globalThis`, `self`,
  `localStorage`, `sessionStorage` or `Math.random`, not even inside a comment;
- no domain module may import `src/render.js` or `src/main.js`;
- rendering and input may use browser APIs in `src/render.js` and `src/main.js`
  only, and rendering must never be the simulation authority.

Product presentation
- a canvas-based top-down arena in `index.html`;
- a coherent neon visual language in `style.css` and `src/render.js`;
- visibly drawn player, enemies, projectiles and relay areas;
- differentiated appearance per enemy archetype;
- a readable HUD showing health, dash state, relay progress and sector;
- explicit relay charging, contested and complete feedback;
- an upgrade-selection screen, a title screen, a pause overlay, a game-over
  screen and a victory screen;
- responsive behavior around 1280x720 and 1920x1080.

Automated tests
- `test/game.test.js` and `test/state-machine.test.js` use `node:test` and
  `node:assert` and contain real behavioral assertions covering pause, restart,
  relay charging, dash and upgrades;
- `package.json` must declare `"type": "module"`, a terminating
  `node --test` test script, no `start` script, no watch script, no `npx`
  invocation, no server command, and no dependencies of any kind.

Documentation
`LOCAL_DEV.md` must remove the fixture marker, explain running `npm test`, and
explain opening `index.html` with the browser's own local open-file action. It
must contain no absolute URL, no `localhost`, no port number and no instruction
to start a server.

Final state
- run `npm test` and wait for it to terminate;
- create exactly one new local commit whose complete message is exactly
  `feat: build playable Neon Relay browser game`;
- leave the worktree and index clean with no untracked file;
- leave zero Git remotes;
- leave no process running;
- stop after that commit; perform no push, no deployment and no optional
  polish.

Completion is established by material presence and change, exact Git state, the
public checkpoint, and the owner-frozen independent behavioral verifier. Saying
the work is complete establishes nothing.
"""


# ---------------------------------------------------------------------------
# Completion conditions: six explicitly separated groups.
# ---------------------------------------------------------------------------

NEON_RELAY_COMPLETION_CONDITIONS_TEXT = f"""Required completion conditions, in six separate groups.

1. Material presence and change
- every one of these exact paths exists as a regular file in the task commit:

  - LOCAL_DEV.md
  - index.html
  - package.json
  - style.css
  - src/random.js
  - src/state-machine.js
  - src/entities.js
  - src/combat.js
  - src/upgrades.js
  - src/game.js
  - src/render.js
  - src/main.js
  - test/game.test.js
  - test/state-machine.test.js

- all fourteen paths are created or materially changed between the fixture
  initial commit and the task commit;
- no additional path is required, and README.md is deliberately not required.

2. Exact Git state
- exactly one new local commit exists after the fixture baseline;
- its complete `%B` message is exactly
  `{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}`;
- no commit-message body, `Co-authored-by`, sign-off, attribution or other
  trailer is present, and no `--trailer` is used;
- the final worktree is clean, the final index is clean, and no untracked file
  remains;
- zero Git remotes exist and nothing is pushed;
- before stopping, `git log -1 --format=%B` is run and its complete output,
  after removing terminal newline characters only, is exactly
  `{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}`;
- if that message is not exact, the same commit is amended during this native
  invocation, no second commit is created, and the exact check is run again.

3. Public checkpoint
- the `npm-test` checkpoint command `npm.cmd test` is run to termination by
  Admissible and must exit zero within its configured bounds.

4. Frozen behavioral verification
- the owner-frozen independent verifier, whose complete source is disclosed
  with this mission, must report every clause satisfied and emit its final
  success line;
- the verifier is the acceptance oracle for behavior; the agent-authored tests
  are a quality floor only.

5. Bounded non-claims
- the following are explicitly not established by any automated step:
  subjective visual quality; control feel and complete human playability;
  anything about rendering, because no browser is launched; anything about
  network or server behavior, because none is started or attempted.

6. Human-only visual review
- visual quality, product coherence and playability remain reserved for a
  separate human review and are never established by this run.

Provider prose establishes none of the above. The statement that the work is
complete does not establish test success, verifier success, playability, visual
quality or product acceptance.
"""


# ---------------------------------------------------------------------------
# Frozen independent behavioral verifier (Node built-ins only).
# ---------------------------------------------------------------------------

NEON_RELAY_VERIFIER_SOURCE = r"""import { readFile, readdir, lstat } from 'node:fs/promises';
import { join, relative as nodeRelative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// Owner-frozen independent behavioral verifier for neon-relay-v1.
//
// Node built-ins only.  It installs nothing, launches no browser, starts no
// server, opens no socket, spawns no subprocess, and never runs the
// agent-authored test files: it reads project text and imports the delivered
// domain modules directly.  The delivered workspace root is its sole
// positional input.  Output is one bounded JSON clause report followed, only
// on a complete pass, by one final success line.

const MESSAGE_BOUND = 320;
const OUTPUT_BOUND = 262144;
const VERIFIER_ID = 'neon-relay-v1';
const SUCCESS_LINE = 'neon-relay behavioral verifier passed';

const REQUIRED_PATHS = [
  'LOCAL_DEV.md',
  'index.html',
  'package.json',
  'style.css',
  'src/random.js',
  'src/state-machine.js',
  'src/entities.js',
  'src/combat.js',
  'src/upgrades.js',
  'src/game.js',
  'src/render.js',
  'src/main.js',
  'test/game.test.js',
  'test/state-machine.test.js',
];

const DOMAIN_MODULES = [
  'src/random.js',
  'src/state-machine.js',
  'src/entities.js',
  'src/combat.js',
  'src/upgrades.js',
  'src/game.js',
];

const STATE_NAMES = ['TITLE', 'RUNNING', 'PAUSED', 'UPGRADE', 'GAME_OVER', 'VICTORY'];
const ENEMY_TYPES = ['chaser', 'shooter', 'splitter'];

const OPERATIONS = [
  'start', 'pause', 'resume', 'advance', 'restart', 'dash', 'spawnEnemy',
  'damageEnemy', 'damagePlayer', 'enterRelayZone', 'leaveRelayZone',
  'removeEnemy', 'completeRelay', 'availableUpgrades', 'applyUpgrade',
  'damageBoss', 'listEnemyTypes', 'getEvents', 'getState',
];

const LEGAL_TRANSITIONS = [
  ['TITLE', 'RUNNING'],
  ['RUNNING', 'PAUSED'],
  ['PAUSED', 'RUNNING'],
  ['RUNNING', 'UPGRADE'],
  ['UPGRADE', 'RUNNING'],
  ['RUNNING', 'GAME_OVER'],
  ['RUNNING', 'VICTORY'],
  ['GAME_OVER', 'TITLE'],
  ['VICTORY', 'TITLE'],
];

const ILLEGAL_TRANSITIONS = [
  ['TITLE', 'PAUSED'],
  ['TITLE', 'UPGRADE'],
  ['TITLE', 'GAME_OVER'],
  ['TITLE', 'VICTORY'],
  ['RUNNING', 'TITLE'],
  ['PAUSED', 'UPGRADE'],
  ['PAUSED', 'GAME_OVER'],
  ['PAUSED', 'VICTORY'],
  ['PAUSED', 'TITLE'],
  ['UPGRADE', 'PAUSED'],
  ['UPGRADE', 'TITLE'],
  ['UPGRADE', 'GAME_OVER'],
  ['UPGRADE', 'VICTORY'],
  ['GAME_OVER', 'RUNNING'],
  ['GAME_OVER', 'PAUSED'],
  ['GAME_OVER', 'UPGRADE'],
  ['GAME_OVER', 'VICTORY'],
  ['VICTORY', 'RUNNING'],
  ['VICTORY', 'PAUSED'],
  ['VICTORY', 'UPGRADE'],
  ['VICTORY', 'GAME_OVER'],
];

const NON_CLAIMS = [
  'subjective visual quality was not independently established',
  'control feel and complete human playability were not independently established',
  'no browser was launched and rendering was not observed',
  'no server was started and no network access was attempted',
];

const NAMESPACE_EXEMPTIONS = [
  'http://www.w3.org/2000/svg',
  'http://www.w3.org/1999/xhtml',
];

const FORBIDDEN_RUNTIME_TOKENS = [
  ['fetch call', /\bfetch\s*\(/],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/],
  ['WebSocket', /\bWebSocket\b/],
  ['EventSource', /\bEventSource\b/],
  ['sendBeacon', /\bsendBeacon\b/],
  ['importScripts', /\bimportScripts\s*\(/],
];

const FORBIDDEN_DOMAIN_TOKENS = [
  ['Date.now', /\bDate\s*\.\s*now\b/],
  ['new Date', /\bnew\s+Date\b/],
  ['performance', /\bperformance\b/],
  ['requestAnimationFrame', /\brequestAnimationFrame\b/],
  ['document', /\bdocument\b/],
  ['window', /\bwindow\b/],
  ['globalThis', /\bglobalThis\b/],
  ['self', /\bself\b/],
  ['localStorage', /\blocalStorage\b/],
  ['sessionStorage', /\bsessionStorage\b/],
  ['Math.random', /\bMath\s*\.\s*random\b/],
];

const TEXT_SUFFIXES = ['.js', '.mjs', '.cjs', '.html', '.htm', '.css', '.json', '.md', '.txt', '.svg'];

const root = process.argv[2];

function bounded(value) {
  const text = typeof value === 'string' ? value : String(value);
  const flat = text.replace(/[\r\n\t]+/g, ' ');
  return flat.length <= MESSAGE_BOUND ? flat : flat.slice(0, MESSAGE_BOUND) + '[truncated]';
}

function stable(value) {
  return JSON.stringify(value, (key, item) => {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const ordered = {};
      for (const name of Object.keys(item).sort()) ordered[name] = item[name];
      return ordered;
    }
    return item;
  });
}

function show(value) {
  if (typeof value === 'string') return JSON.stringify(value);
  if (value === undefined) return 'undefined';
  try {
    return bounded(JSON.stringify(value));
  } catch {
    return String(value);
  }
}

function need(condition, message) {
  if (!condition) throw new Error(message);
}

function same(actual, expected, message) {
  if (!Object.is(actual, expected)) {
    throw new Error(message + ' (expected ' + show(expected) + ', observed ' + show(actual) + ')');
  }
}

function deep(actual, expected, message) {
  if (stable(actual) !== stable(expected)) {
    throw new Error(message + ' (expected ' + bounded(stable(expected)) + ', observed ' + bounded(stable(actual)) + ')');
  }
}

function differs(actual, expected, message) {
  if (stable(actual) === stable(expected)) throw new Error(message);
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function needFinite(value, label) {
  need(isFiniteNumber(value), label + ' must be a finite number, observed ' + show(value));
}

function needBool(value, label) {
  need(typeof value === 'boolean', label + ' must be a boolean, observed ' + show(value));
}

function needPlainObject(value, label) {
  need(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    label + ' must be a plain object, observed ' + show(value),
  );
}

function toRelative(absolutePath) {
  return nodeRelative(root, absolutePath).split(sep).join('/');
}

async function walk(directory, accumulated) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return accumulated;
  }
  for (const entry of entries.slice().sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) await walk(full, accumulated);
    else if (entry.isFile()) accumulated.push(full);
  }
  return accumulated;
}

async function readText(relativePath) {
  return await readFile(join(root, ...relativePath.split('/')), 'utf8');
}

async function isRegularFile(relativePath) {
  try {
    const metadata = await lstat(join(root, ...relativePath.split('/')));
    return metadata.isFile();
  } catch {
    return false;
  }
}

async function exists(relativePath) {
  try {
    await lstat(join(root, ...relativePath.split('/')));
    return true;
  } catch {
    return false;
  }
}

function strippedOfExemptions(text) {
  let result = text;
  for (const exemption of NAMESPACE_EXEMPTIONS) result = result.split(exemption).join('');
  return result;
}

const results = [];

async function clause(id, body) {
  try {
    const message = await body();
    results.push({ id, ok: true, message: bounded(message || 'satisfied') });
  } catch (error) {
    const detail = error && error.message ? error.message : error;
    results.push({ id, ok: false, message: bounded(detail) });
  }
}

// --------------------------------------------------------------------------
// Structural clauses.
// --------------------------------------------------------------------------

let projectFiles = [];
let projectTexts = new Map();

await clause('C01_required_paths', async () => {
  need(typeof root === 'string' && root.length > 0, 'workspace root argument is required');
  need(process.argv.length === 3, 'exactly one positional workspace argument is accepted');
  const missing = [];
  for (const candidate of REQUIRED_PATHS) {
    if (!(await isRegularFile(candidate))) missing.push(candidate);
  }
  need(missing.length === 0, 'required regular files are missing: ' + missing.join(', '));
  return 'all 14 required paths exist as regular files';
});

await clause('C02_package_contract', async () => {
  const raw = await readText('package.json');
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (error) {
    throw new Error('package.json is not parseable JSON: ' + error.message);
  }
  needPlainObject(manifest, 'package.json root');
  same(manifest.type, 'module', 'package type must be module');
  needPlainObject(manifest.scripts, 'package scripts');
  need(typeof manifest.scripts.test === 'string' && manifest.scripts.test.length > 0, 'a test script is required');
  const test = manifest.scripts.test;
  need(/(^|[\s;&|])node(\.exe)?[\s]/.test(test), 'test script must invoke node directly, observed ' + show(test));
  need(/(^|\s)--test(\s|$)/.test(test), 'test script must use the terminating node --test runner, observed ' + show(test));
  need(!/--watch/.test(test), 'test script must not watch');
  need(manifest.scripts.start === undefined, 'no start script may be defined');
  for (const [name, value] of Object.entries(manifest.scripts)) {
    const combined = name + ' ' + String(value);
    need(!/watch/i.test(combined), 'no watch script may be defined: ' + show(name));
    need(!/\bnpx\b/i.test(combined), 'no script may invoke npx: ' + show(name));
    need(
      !/(http-server|live-server|\bserve\b|http\.server|--listen|\blisten\b|\bserver\b)/i.test(combined),
      'no script may start a server: ' + show(name),
    );
  }
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const value = manifest[field];
    need(
      value === undefined || (value !== null && typeof value === 'object' && Object.keys(value).length === 0),
      'package.json must declare no ' + field,
    );
  }
  return 'module type, terminating node --test script, no start/watch/npx/server script, zero dependencies';
});

await clause('C03_no_external_runtime', async () => {
  need(!(await exists('node_modules')), 'node_modules must not exist');
  projectFiles = await walk(root, []);
  need(projectFiles.length > 0, 'workspace contains no inspectable file');
  const findings = [];
  for (const absolute of projectFiles) {
    const rel = toRelative(absolute);
    if (!TEXT_SUFFIXES.some((suffix) => rel.endsWith(suffix))) continue;
    let text;
    try {
      text = await readFile(absolute, 'utf8');
    } catch (error) {
      throw new Error('project file is unreadable: ' + rel);
    }
    projectTexts.set(rel, text);
    if (text.includes('NEON_RELAY_BLANK_FIXTURE_V1')) findings.push(rel + ': fixture marker present');
    const scanned = strippedOfExemptions(text);
    const url = scanned.match(/https?:\/\/[^\s'"`)<>]*/);
    if (url) findings.push(rel + ': absolute URL ' + url[0].slice(0, 60));
    for (const [label, pattern] of FORBIDDEN_RUNTIME_TOKENS) {
      if (pattern.test(scanned)) findings.push(rel + ': forbidden network token ' + label);
    }
  }
  need(findings.length === 0, 'external-runtime findings: ' + findings.slice(0, 6).join(' | '));
  const index = projectTexts.get('index.html');
  need(typeof index === 'string', 'index.html must be readable UTF-8 text');
  need(/<canvas\b/i.test(index), 'index.html must contain a canvas element');
  need(/Neon Relay/.test(index), 'index.html must name the product Neon Relay');
  const remote = index.match(/(?:src|href)\s*=\s*['"]\s*(?:\/\/|https?:)/i);
  need(remote === null, 'index.html must reference no remote script, stylesheet or asset');
  const doc = projectTexts.get('LOCAL_DEV.md');
  need(typeof doc === 'string', 'LOCAL_DEV.md must be readable UTF-8 text');
  need(!/https?:\/\//i.test(doc), 'LOCAL_DEV.md must contain no absolute URL');
  const serverHint = doc.match(/(npm\s+start|http-server|live-server|http\.server|npx\s+serve|localhost|127\.0\.0\.1|\bport\s+\d)/i);
  need(serverHint === null, 'LOCAL_DEV.md must contain no server instruction, observed ' + show(serverHint && serverHint[0]));
  need(/npm\s+test/.test(doc), 'LOCAL_DEV.md must explain running npm test');
  return 'no node_modules, no absolute URL, no network API, canvas present, product named, marker removed';
});

await clause('C04_domain_is_pure', async () => {
  const findings = [];
  for (const modulePath of DOMAIN_MODULES) {
    const text = projectTexts.get(modulePath) ?? (await readText(modulePath));
    for (const [label, pattern] of FORBIDDEN_DOMAIN_TOKENS) {
      if (pattern.test(text)) findings.push(modulePath + ': ' + label);
    }
    const staticImport = text.match(/from\s*['"][^'"]*\b(?:render|main)\.js['"]/);
    const dynamicImport = text.match(/import\s*\(\s*['"][^'"]*\b(?:render|main)\.js['"]/);
    if (staticImport) findings.push(modulePath + ': imports the renderer or entry module');
    if (dynamicImport) findings.push(modulePath + ': dynamically imports the renderer or entry module');
  }
  need(findings.length === 0, 'domain purity findings: ' + findings.slice(0, 6).join(' | '));
  return 'six domain modules reference no browser global, clock or uncontrolled randomness and import no renderer';
});

await clause('C05_agent_tests_are_behavioural', async () => {
  let assertions = 0;
  let combined = '';
  for (const testPath of ['test/game.test.js', 'test/state-machine.test.js']) {
    const text = projectTexts.get(testPath) ?? (await readText(testPath));
    need(/from\s*['"]node:test['"]/.test(text), testPath + ' must use the node:test runner');
    need(/node:assert/.test(text), testPath + ' must use node:assert');
    const local = (text.match(/\bassert(?:\.[A-Za-z]+)?\s*\(/g) || []).length;
    need(local >= 3, testPath + ' must contain at least 3 assertions, observed ' + local);
    assertions += local;
    combined += '\n' + text;
  }
  need(assertions >= 12, 'agent tests must contain at least 12 assertions, observed ' + assertions);
  const lowered = combined.toLowerCase();
  const uncovered = ['pause', 'restart', 'relay', 'dash', 'upgrade'].filter((topic) => !lowered.includes(topic));
  need(uncovered.length === 0, 'agent tests do not mention required behavior: ' + uncovered.join(', '));
  return 'both agent test files assert real behavior over pause, restart, relay, dash and upgrades (quality floor only, not the oracle)';
});

// --------------------------------------------------------------------------
// Domain surface and behavior.
// --------------------------------------------------------------------------

let domain = null;

function surface() {
  need(domain !== null, 'domain surface is unavailable because C06_domain_surface_importable failed');
  return domain;
}

function newGame(seed) {
  const created = surface().createGame({ seed });
  needPlainObject(created, 'createGame result');
  return created;
}

function snapshotOf(game) {
  const snapshot = game.getState();
  needPlainObject(snapshot, 'getState snapshot');
  need(STATE_NAMES.includes(snapshot.state), 'snapshot state must be a known state, observed ' + show(snapshot.state));
  needFinite(snapshot.timeMs, 'snapshot timeMs');
  need(snapshot.timeMs >= 0, 'snapshot timeMs must never be negative');
  needPlainObject(snapshot.player, 'snapshot player');
  for (const field of ['health', 'maxHealth', 'x', 'y', 'dashCooldownMs', 'dashCooldownTotalMs']) {
    needFinite(snapshot.player[field], 'snapshot player.' + field);
  }
  need(snapshot.player.health >= 0, 'player health must never be negative');
  need(snapshot.player.health <= snapshot.player.maxHealth, 'player health must never exceed maxHealth');
  need(snapshot.player.dashCooldownMs >= 0, 'dash cooldown must never be negative');
  need(Array.isArray(snapshot.relays) && snapshot.relays.length === 3, 'snapshot must expose exactly three relays');
  snapshot.relays.forEach((relay, index) => {
    needPlainObject(relay, 'relay ' + index);
    same(relay.index, index, 'relay index must equal its position');
    needFinite(relay.charge, 'relay ' + index + ' charge');
    needFinite(relay.fullCharge, 'relay ' + index + ' fullCharge');
    need(relay.fullCharge > 0, 'relay ' + index + ' fullCharge must be positive');
    need(relay.charge >= 0 && relay.charge <= relay.fullCharge, 'relay ' + index + ' charge must stay within [0, fullCharge]');
    needBool(relay.complete, 'relay ' + index + ' complete');
    needBool(relay.contested, 'relay ' + index + ' contested');
    needBool(relay.occupied, 'relay ' + index + ' occupied');
  });
  needFinite(snapshot.activeRelayIndex, 'snapshot activeRelayIndex');
  needFinite(snapshot.relaysComplete, 'snapshot relaysComplete');
  need(Array.isArray(snapshot.enemies), 'snapshot enemies must be an array');
  need(Number.isInteger(snapshot.maxEnemies) && snapshot.maxEnemies >= 4 && snapshot.maxEnemies <= 128, 'maxEnemies must be an integer in [4, 128]');
  need(snapshot.enemies.length <= snapshot.maxEnemies, 'enemy count must never exceed maxEnemies');
  needPlainObject(snapshot.arena, 'snapshot arena');
  needFinite(snapshot.arena.width, 'arena width');
  needFinite(snapshot.arena.height, 'arena height');
  need(snapshot.arena.width > 0 && snapshot.arena.height > 0, 'arena extents must be positive');
  snapshot.enemies.forEach((enemy, index) => {
    needPlainObject(enemy, 'enemy ' + index);
    need(typeof enemy.id === 'string' && enemy.id.length > 0, 'enemy ' + index + ' id must be a non-empty string');
    need(ENEMY_TYPES.includes(enemy.type), 'enemy ' + index + ' type must be a known archetype, observed ' + show(enemy.type));
    needFinite(enemy.health, 'enemy ' + index + ' health');
    need(enemy.health > 0, 'listed enemies must be alive');
    need(Number.isInteger(enemy.generation) && enemy.generation >= 0, 'enemy ' + index + ' generation must be a non-negative integer');
    needFinite(enemy.x, 'enemy ' + index + ' x');
    needFinite(enemy.y, 'enemy ' + index + ' y');
  });
  need(Array.isArray(snapshot.projectiles), 'snapshot projectiles must be an array');
  need(Array.isArray(snapshot.appliedUpgrades), 'snapshot appliedUpgrades must be an array');
  need(Array.isArray(snapshot.pendingUpgradeChoices), 'snapshot pendingUpgradeChoices must be an array');
  if (snapshot.boss !== null) {
    needPlainObject(snapshot.boss, 'snapshot boss');
    needFinite(snapshot.boss.health, 'boss health');
    needFinite(snapshot.boss.maxHealth, 'boss maxHealth');
    needBool(snapshot.boss.active, 'boss active');
    need(snapshot.boss.health >= 0 && snapshot.boss.health <= snapshot.boss.maxHealth, 'boss health must stay within [0, maxHealth]');
  }
  return snapshot;
}

function eventsOf(game) {
  const events = game.getEvents();
  need(Array.isArray(events), 'getEvents must return an array');
  events.forEach((event, index) => {
    needPlainObject(event, 'event ' + index);
    need(typeof event.type === 'string' && event.type.length > 0, 'event ' + index + ' type must be a non-empty string');
    needFinite(event.timeMs, 'event ' + index + ' timeMs');
  });
  return events;
}

function offerFrom(game) {
  const offers = game.availableUpgrades();
  need(Array.isArray(offers) && offers.length === 3, 'an upgrade offer must contain exactly three choices, observed ' + show(offers && offers.length));
  const ids = [];
  for (const offer of offers) {
    needPlainObject(offer, 'upgrade choice');
    need(typeof offer.id === 'string' && offer.id.length > 0, 'upgrade choice id must be a non-empty string');
    need(typeof offer.name === 'string' && offer.name.length > 0, 'upgrade choice name must be a non-empty string');
    need(typeof offer.description === 'string' && offer.description.length > 0, 'upgrade choice description must be a non-empty string');
    ids.push(offer.id);
  }
  need(new Set(ids).size === 3, 'upgrade choices must be distinct, observed ' + show(ids));
  const applied = snapshotOf(game).appliedUpgrades;
  need(ids.every((id) => !applied.includes(id)), 'an offer must never repeat an already-applied upgrade');
  return offers;
}

function reachUpgradeAndApply(game, index) {
  same(game.completeRelay(), true, 'completeRelay must succeed for relay ' + index);
  same(snapshotOf(game).state, 'UPGRADE', 'completing relay ' + index + ' must enter UPGRADE');
  const offers = offerFrom(game);
  same(game.applyUpgrade(offers[0].id), true, 'the first upgrade application must succeed');
  same(snapshotOf(game).state, 'RUNNING', 'applying an upgrade must return the domain to RUNNING');
  return offers[0].id;
}

await clause('C06_domain_surface_importable', async () => {
  const loaded = {};
  for (const modulePath of DOMAIN_MODULES) {
    const url = pathToFileURL(join(root, ...modulePath.split('/'))).href;
    try {
      loaded[modulePath] = await import(url);
    } catch (error) {
      throw new Error('domain module ' + modulePath + ' is not importable: ' + (error && error.message ? error.message : error));
    }
    need(Object.keys(loaded[modulePath]).length > 0, 'domain module ' + modulePath + ' must export at least one binding');
  }
  const randomModule = loaded['src/random.js'];
  const machineModule = loaded['src/state-machine.js'];
  const gameModule = loaded['src/game.js'];
  need(typeof randomModule.createRandom === 'function', 'src/random.js must export createRandom');
  need(typeof machineModule.legalTransitions === 'function', 'src/state-machine.js must export legalTransitions');
  need(typeof machineModule.canTransition === 'function', 'src/state-machine.js must export canTransition');
  needPlainObject(machineModule.STATES, 'STATES');
  deep(Object.keys(machineModule.STATES).slice().sort(), STATE_NAMES.slice().sort(), 'STATES must expose exactly the six domain states');
  for (const name of STATE_NAMES) same(machineModule.STATES[name], name, 'STATES.' + name + ' must equal its own name');
  need(typeof gameModule.createGame === 'function', 'src/game.js must export createGame');
  const generator = randomModule.createRandom(1);
  needPlainObject(generator, 'createRandom result');
  need(typeof generator.next === 'function', 'createRandom result must expose next()');
  for (let index = 0; index < 8; index += 1) {
    const value = generator.next();
    needFinite(value, 'createRandom next() value');
    need(value >= 0 && value < 1, 'createRandom next() must stay within [0, 1), observed ' + show(value));
  }
  domain = { random: randomModule, machine: machineModule, game: gameModule, createGame: gameModule.createGame };
  const game = newGame(1);
  const missing = OPERATIONS.filter((name) => typeof game[name] !== 'function');
  need(missing.length === 0, 'game object is missing required operations: ' + missing.join(', '));
  const snapshot = snapshotOf(game);
  same(snapshot.state, 'TITLE', 'a fresh game must start in TITLE');
  same(snapshot.timeMs, 0, 'a fresh game must start at time zero');
  same(snapshot.relaysComplete, 0, 'a fresh game must have no relay complete');
  same(snapshot.boss, null, 'a fresh game must have no boss');
  same(snapshot.enemies.length, 0, 'a fresh game must have no enemy');
  same(snapshot.appliedUpgrades.length, 0, 'a fresh game must have no applied upgrade');
  same(eventsOf(game).length, 0, 'a fresh game must have no event');
  deep(game.listEnemyTypes().slice().sort(), ENEMY_TYPES.slice().sort(), 'listEnemyTypes must expose exactly the three archetypes');
  return 'complete domain surface imported and the pinned snapshot, event and operation contract holds';
});

await clause('C07_seeded_determinism', async () => {
  const { createRandom } = surface().random;
  const sequence = (seed) => {
    const generator = createRandom(seed);
    const values = [];
    for (let index = 0; index < 24; index += 1) values.push(generator.next());
    return values;
  };
  deep(sequence(1234), sequence(1234), 'the same seed must reproduce the same random sequence');
  differs(sequence(1234), sequence(4321), 'different seeds must produce different random sequences');
  const drive = (game) => {
    game.start();
    game.advance(100);
    game.spawnEnemy('chaser');
    game.enterRelayZone();
    game.advance(500);
    game.dash();
    game.advance(250);
    game.spawnEnemy('shooter');
    game.damagePlayer(1);
    game.advance(125);
    game.leaveRelayZone();
    game.advance(75);
  };
  const first = newGame(2024);
  const second = newGame(2024);
  drive(first);
  drive(second);
  deep(snapshotOf(first), snapshotOf(second), 'the same seed and operation sequence must produce identical snapshots');
  deep(eventsOf(first), eventsOf(second), 'the same seed and operation sequence must produce identical events');
  const third = newGame(2024);
  drive(third);
  deep(snapshotOf(third), snapshotOf(first), 'a third identical run must not drift with wall-clock time');
  return 'seeded random and the full driven operation sequence are deeply reproducible';
});

await clause('C08_paused_does_not_progress', async () => {
  const game = newGame(3);
  game.start();
  game.enterRelayZone();
  game.spawnEnemy('chaser');
  game.advance(200);
  game.pause();
  same(snapshotOf(game).state, 'PAUSED', 'pause must enter PAUSED from RUNNING');
  const frozenState = stable(snapshotOf(game));
  const frozenEvents = stable(eventsOf(game));
  const pausedTime = snapshotOf(game).timeMs;
  need(pausedTime > 0, 'time must have advanced before pausing');
  for (let index = 0; index < 5; index += 1) game.advance(1000);
  same(stable(snapshotOf(game)), frozenState, 'advancing while PAUSED must change nothing');
  same(stable(eventsOf(game)), frozenEvents, 'advancing while PAUSED must emit no event');
  game.resume();
  same(snapshotOf(game).state, 'RUNNING', 'resume must return to RUNNING');
  game.advance(100);
  need(snapshotOf(game).timeMs > pausedTime, 'time must advance again after resume');
  return 'a paused simulation neither advances time nor emits events, and resume restores progress';
});

await clause('C09_restart_resets', async () => {
  const game = newGame(5);
  const initialState = stable(snapshotOf(game));
  const initialEvents = stable(eventsOf(game));
  game.start();
  game.damagePlayer(1);
  game.spawnEnemy('shooter');
  game.enterRelayZone();
  game.advance(1000);
  game.dash();
  const appliedId = reachUpgradeAndApply(game, 1);
  need(snapshotOf(game).appliedUpgrades.includes(appliedId), 'an applied upgrade must be recorded');
  need(snapshotOf(game).player.health < snapshotOf(game).player.maxHealth, 'the player must have taken damage');
  game.advance(500);
  const maxHealth = snapshotOf(game).player.maxHealth;
  game.damagePlayer(maxHealth * 10);
  same(snapshotOf(game).state, 'GAME_OVER', 'lethal damage must enter GAME_OVER');
  game.restart();
  const after = snapshotOf(game);
  same(after.state, 'TITLE', 'restart must return to TITLE');
  same(after.timeMs, 0, 'restart must reset simulation time');
  same(after.player.health, after.player.maxHealth, 'restart must restore full health');
  same(after.player.dashCooldownMs, 0, 'restart must clear the dash cooldown');
  same(after.appliedUpgrades.length, 0, 'restart must discard every applied upgrade');
  same(after.enemies.length, 0, 'restart must clear every enemy');
  same(after.relaysComplete, 0, 'restart must reset relay progress');
  same(after.boss, null, 'restart must clear the boss');
  need(after.relays.every((relay) => relay.charge === 0 && relay.complete === false), 'restart must discharge every relay');
  same(stable(after), initialState, 'restart must reproduce the freshly created snapshot exactly');
  same(stable(eventsOf(game)), initialEvents, 'restart must clear the event list');
  return 'restart discards damage, upgrades, enemies, relay progress, boss and events and reproduces the fresh snapshot';
});

await clause('C10_legal_transitions', async () => {
  const { legalTransitions, canTransition } = surface().machine;
  const pairs = legalTransitions();
  need(Array.isArray(pairs), 'legalTransitions must return an array');
  for (const pair of pairs) {
    need(Array.isArray(pair) && pair.length === 2, 'each legal transition must be a two-element array, observed ' + show(pair));
    need(STATE_NAMES.includes(pair[0]) && STATE_NAMES.includes(pair[1]), 'legal transitions must reference known states, observed ' + show(pair));
  }
  const encoded = pairs.map((pair) => pair[0] + '->' + pair[1]);
  need(new Set(encoded).size === encoded.length, 'legal transitions must not repeat');
  deep(encoded.slice().sort(), LEGAL_TRANSITIONS.map((pair) => pair[0] + '->' + pair[1]).sort(), 'the legal transition set must be exactly the pinned set');
  for (const [from, to] of LEGAL_TRANSITIONS) {
    same(canTransition(from, to), true, 'canTransition must accept ' + from + '->' + to);
  }
  for (const [from, to] of ILLEGAL_TRANSITIONS) {
    same(canTransition(from, to), false, 'canTransition must reject ' + from + '->' + to);
  }
  for (const name of STATE_NAMES) same(canTransition(name, name), false, 'canTransition must reject the self transition ' + name);
  same(canTransition('BOGUS', 'RUNNING'), false, 'canTransition must reject an unknown source state');
  same(canTransition('RUNNING', 'BOGUS'), false, 'canTransition must reject an unknown target state');
  same(canTransition(1, 2), false, 'canTransition must reject non-string input');
  same(canTransition(undefined, undefined), false, 'canTransition must reject undefined input');
  const game = newGame(1);
  game.pause();
  same(snapshotOf(game).state, 'TITLE', 'pause must be refused from TITLE');
  game.resume();
  same(snapshotOf(game).state, 'TITLE', 'resume must be refused from TITLE');
  game.restart();
  same(snapshotOf(game).state, 'TITLE', 'restart must be inert in TITLE');
  same(game.dash(), false, 'dash must be refused outside RUNNING');
  same(game.completeRelay(), false, 'completeRelay must be refused outside RUNNING');
  same(game.spawnEnemy('chaser'), null, 'spawnEnemy must be refused outside RUNNING');
  game.advance(100);
  same(snapshotOf(game).timeMs, 0, 'advance must be inert in TITLE');
  game.start();
  same(snapshotOf(game).state, 'RUNNING', 'start must enter RUNNING from TITLE');
  game.start();
  same(snapshotOf(game).state, 'RUNNING', 'a second start must be inert');
  game.resume();
  same(snapshotOf(game).state, 'RUNNING', 'resume must be inert while RUNNING');
  game.restart();
  same(snapshotOf(game).state, 'RUNNING', 'restart must be refused while RUNNING');
  return 'the pinned legal transition set is exact and every illegal transition is refused in the machine and at runtime';
});

await clause('C11_dash_cooldown_bounded', async () => {
  const game = newGame(7);
  game.start();
  const total = snapshotOf(game).player.dashCooldownTotalMs;
  need(total > 0 && Number.isFinite(total), 'dashCooldownTotalMs must be positive and finite, observed ' + show(total));
  same(snapshotOf(game).player.dashCooldownMs, 0, 'a fresh run must permit an immediate dash');
  same(game.dash(), true, 'the first dash must succeed');
  const started = snapshotOf(game).player.dashCooldownMs;
  need(started > 0 && started <= total, 'a started dash must set a cooldown within (0, total], observed ' + show(started));
  same(game.dash(), false, 'a dash must be refused while the cooldown is running');
  need(snapshotOf(game).player.dashCooldownMs <= started, 'a refused dash must never raise the remaining cooldown');
  game.advance(Math.floor(total / 2));
  const halfway = snapshotOf(game).player.dashCooldownMs;
  need(halfway > 0 && halfway < started, 'the cooldown must decay with advanced time, observed ' + show(halfway));
  same(game.dash(), false, 'a dash must remain refused halfway through the cooldown');
  game.advance(total);
  same(snapshotOf(game).player.dashCooldownMs, 0, 'the cooldown must reach exactly zero and never go negative');
  same(game.dash(), true, 'a dash must succeed once the cooldown has elapsed');
  same(snapshotOf(game).player.dashCooldownMs, total, 'a new dash must reset the cooldown to its total');
  return 'the dash cooldown is positive, bounded, monotonically decaying and never bypassed';
});

await clause('C12_upgrade_applied_once', async () => {
  const game = newGame(11);
  game.start();
  deep(game.availableUpgrades(), [], 'no upgrade may be offered while RUNNING');
  same(game.applyUpgrade('anything'), false, 'applyUpgrade must be refused outside UPGRADE');
  same(game.completeRelay(), true, 'completing the first relay must succeed');
  same(snapshotOf(game).state, 'UPGRADE', 'completing the first relay must enter UPGRADE');
  same(snapshotOf(game).relaysComplete, 1, 'the first relay must be recorded complete');
  const offers = offerFrom(game);
  deep(snapshotOf(game).pendingUpgradeChoices.slice().sort(), offers.map((offer) => offer.id).sort(), 'the snapshot must expose the pending offer ids');
  same(game.applyUpgrade('not-an-offered-upgrade'), false, 'an unknown upgrade id must be refused');
  same(game.applyUpgrade(offers[0].id), true, 'the offered upgrade must apply once');
  same(snapshotOf(game).state, 'RUNNING', 'applying an upgrade must close the offer and resume RUNNING');
  same(game.applyUpgrade(offers[0].id), false, 'the same upgrade must never apply twice');
  same(game.applyUpgrade(offers[1].id), false, 'a second choice from a closed offer must be refused');
  deep(snapshotOf(game).appliedUpgrades, [offers[0].id], 'exactly one upgrade may be recorded per offer');
  deep(game.availableUpgrades(), [], 'a closed offer must expose no choice');
  same(game.completeRelay(), true, 'completing the second relay must succeed');
  same(snapshotOf(game).state, 'UPGRADE', 'completing the second relay must enter UPGRADE');
  same(snapshotOf(game).relaysComplete, 2, 'the second relay must be recorded complete');
  const secondOffers = offerFrom(game);
  same(game.applyUpgrade(secondOffers[0].id), true, 'the second offer must apply once');
  const applied = snapshotOf(game).appliedUpgrades;
  same(applied.length, 2, 'exactly two upgrades may be applied after two offers');
  need(applied.includes(offers[0].id), 'an applied upgrade must persist for the current run');
  need(applied.includes(secondOffers[0].id), 'the second applied upgrade must be recorded');
  return 'each offer presents three distinct choices, exactly one applies once, and applied upgrades persist';
});

await clause('C13_splitter_divides_once', async () => {
  const game = newGame(13);
  game.start();
  const spawned = game.spawnEnemy('splitter');
  needPlainObject(spawned, 'spawned splitter');
  same(spawned.type, 'splitter', 'the spawned archetype must be a splitter');
  same(spawned.generation, 0, 'a spawned splitter must be generation zero');
  need(spawned.health > 0, 'a spawned splitter must be alive');
  same(snapshotOf(game).enemies.length, 1, 'exactly one enemy must exist after one spawn');
  same(game.damageEnemy(spawned.id, spawned.health), true, 'lethal damage to the splitter must be accepted');
  const children = snapshotOf(game).enemies;
  same(children.length, 2, 'a generation-zero splitter must divide into exactly two enemies');
  need(children.every((child) => child.type === 'splitter'), 'splitter children must be splitters');
  need(children.every((child) => child.generation === 1), 'splitter children must be generation one');
  need(children.every((child) => child.health > 0), 'splitter children must be alive');
  need(new Set(children.map((child) => child.id)).size === 2, 'splitter children must have distinct ids');
  same(game.damageEnemy(children[0].id, children[0].health), true, 'lethal damage to a child must be accepted');
  same(snapshotOf(game).enemies.length, 1, 'a generation-one splitter must never divide');
  const survivor = snapshotOf(game).enemies[0];
  same(game.damageEnemy(survivor.id, survivor.health), true, 'lethal damage to the last child must be accepted');
  same(snapshotOf(game).enemies.length, 0, 'the arena must empty once both children die');
  same(game.damageEnemy('no-such-enemy', 1), false, 'damaging an unknown enemy must be refused');
  for (const type of ['chaser', 'shooter']) {
    const other = game.spawnEnemy(type);
    needPlainObject(other, 'spawned ' + type);
    same(game.damageEnemy(other.id, other.health), true, 'lethal damage to a ' + type + ' must be accepted');
    same(snapshotOf(game).enemies.length, 0, 'a dying ' + type + ' must never divide');
  }
  const removable = game.spawnEnemy('splitter');
  same(game.removeEnemy(removable.id), true, 'removing an enemy must be accepted');
  same(snapshotOf(game).enemies.length, 0, 'a removed splitter must not divide');
  same(game.removeEnemy('no-such-enemy'), false, 'removing an unknown enemy must be refused');
  return 'a generation-zero splitter divides into exactly two generation-one splitters that never divide again';
});

await clause('C14_relay_contesting_law', async () => {
  const game = newGame(17);
  game.start();
  same(snapshotOf(game).activeRelayIndex, 0, 'the first relay must be active at the start of a run');
  const relay = () => snapshotOf(game).relays[0];
  same(relay().charge, 0, 'a fresh relay must hold no charge');
  game.advance(500);
  same(relay().charge, 0, 'an unoccupied relay must never gain charge');
  same(relay().occupied, false, 'an unoccupied relay must not report occupation');
  game.enterRelayZone();
  same(relay().occupied, true, 'entering the zone must report occupation');
  same(relay().contested, false, 'an empty zone must not be contested');
  game.advance(500);
  const charged = relay().charge;
  need(charged > 0, 'an occupied, uncontested relay must gain charge, observed ' + show(charged));
  const contester = game.spawnEnemy('chaser');
  needPlainObject(contester, 'contesting enemy');
  same(relay().contested, true, 'a living enemy in the zone must contest the relay');
  const held = relay().charge;
  game.advance(1000);
  need(relay().charge <= held, 'a contested relay must never gain charge, observed ' + show(relay().charge) + ' from ' + show(held));
  game.advance(1000);
  need(relay().charge <= held, 'a contested relay must still never gain charge');
  same(game.removeEnemy(contester.id), true, 'removing the contesting enemy must be accepted');
  same(relay().contested, false, 'an emptied zone must stop reporting contest');
  const resumeFrom = relay().charge;
  game.advance(1000);
  need(relay().charge > resumeFrom, 'an uncontested, occupied relay must resume charging');
  game.leaveRelayZone();
  const parked = relay().charge;
  game.advance(1000);
  need(relay().charge <= parked, 'leaving the zone must stop charging');
  same(relay().occupied, false, 'leaving the zone must clear occupation');
  game.enterRelayZone();
  game.advance(1000000);
  const finished = snapshotOf(game).relays[0];
  same(finished.charge, finished.fullCharge, 'sustained uncontested occupation must reach exactly fullCharge');
  same(finished.complete, true, 'a fully charged relay must be complete');
  need(snapshotOf(game).relaysComplete >= 1, 'a completed relay must be counted');
  return 'charge accrues only while occupied and uncontested, never increases while contested, and is bounded by fullCharge';
});

await clause('C15_game_over_stops_simulation', async () => {
  const game = newGame(19);
  game.start();
  game.enterRelayZone();
  game.spawnEnemy('chaser');
  game.advance(300);
  const maxHealth = snapshotOf(game).player.maxHealth;
  game.damagePlayer(maxHealth * 10);
  const dead = snapshotOf(game);
  same(dead.state, 'GAME_OVER', 'zero health must enter GAME_OVER');
  same(dead.player.health, 0, 'game over requires player health exactly zero');
  const frozenState = stable(dead);
  const frozenEvents = stable(eventsOf(game));
  for (let index = 0; index < 5; index += 1) game.advance(5000);
  same(stable(snapshotOf(game)), frozenState, 'the simulation must be inert after GAME_OVER');
  same(stable(eventsOf(game)), frozenEvents, 'no event may be emitted after GAME_OVER');
  same(game.dash(), false, 'dash must be refused after GAME_OVER');
  same(game.spawnEnemy('chaser'), null, 'spawnEnemy must be refused after GAME_OVER');
  same(game.applyUpgrade('anything'), false, 'applyUpgrade must be refused after GAME_OVER');
  same(game.damageBoss(1), false, 'damageBoss must be refused after GAME_OVER');
  same(game.completeRelay(), false, 'completeRelay must be refused after GAME_OVER');
  game.pause();
  same(snapshotOf(game).state, 'GAME_OVER', 'pause must be refused after GAME_OVER');
  game.resume();
  same(snapshotOf(game).state, 'GAME_OVER', 'resume must be refused after GAME_OVER');
  game.enterRelayZone();
  game.damagePlayer(5);
  same(stable(snapshotOf(game)), frozenState, 'no operation may mutate the terminal snapshot');
  game.restart();
  same(snapshotOf(game).state, 'TITLE', 'restart must be accepted from GAME_OVER');
  return 'GAME_OVER requires exactly zero health and freezes the simulation against every further operation';
});

await clause('C16_victory_requires_relays_and_boss', async () => {
  const game = newGame(23);
  game.start();
  same(snapshotOf(game).boss, null, 'no boss may exist before the third relay');
  same(game.damageBoss(1000000), false, 'damageBoss must be refused while no boss exists');
  need(snapshotOf(game).state !== 'VICTORY', 'victory must not be reachable before any relay completes');
  reachUpgradeAndApply(game, 1);
  need(snapshotOf(game).state !== 'VICTORY', 'victory must not be reachable after one relay');
  same(snapshotOf(game).boss, null, 'no boss may exist after one relay');
  reachUpgradeAndApply(game, 2);
  const twoDone = snapshotOf(game);
  same(twoDone.relaysComplete, 2, 'two relays must be recorded complete');
  same(twoDone.boss, null, 'no boss may exist after two relays');
  need(twoDone.state !== 'VICTORY', 'victory must not be reachable after two relays');
  same(game.damageBoss(1000000), false, 'damageBoss must remain refused after two relays');
  same(game.completeRelay(), true, 'completing the third relay must succeed');
  const bossPhase = snapshotOf(game);
  same(bossPhase.relaysComplete, 3, 'three relays must be recorded complete');
  same(bossPhase.state, 'RUNNING', 'completing the third relay must keep the run in RUNNING');
  needPlainObject(bossPhase.boss, 'boss after the third relay');
  same(bossPhase.boss.active, true, 'the boss must be active after the third relay');
  need(bossPhase.boss.health > 0, 'the boss must start with positive health');
  same(bossPhase.boss.health, bossPhase.boss.maxHealth, 'the boss must start at full health');
  deep(game.availableUpgrades(), [], 'no upgrade offer may follow the third relay');
  same(game.damageBoss(1), true, 'the active boss must accept damage');
  const wounded = snapshotOf(game);
  need(wounded.boss.health > 0, 'partial boss damage must not end the run');
  need(wounded.state !== 'VICTORY', 'victory requires boss health exactly zero');
  same(game.damageBoss(bossPhase.boss.maxHealth * 10), true, 'lethal boss damage must be accepted');
  const won = snapshotOf(game);
  same(won.boss.health, 0, 'victory requires boss health exactly zero');
  same(won.relaysComplete, 3, 'victory requires all three relays complete');
  same(won.state, 'VICTORY', 'zero boss health with three relays complete must enter VICTORY');
  const frozenState = stable(won);
  const frozenEvents = stable(eventsOf(game));
  for (let index = 0; index < 5; index += 1) game.advance(5000);
  same(stable(snapshotOf(game)), frozenState, 'the simulation must be inert after VICTORY');
  same(stable(eventsOf(game)), frozenEvents, 'no event may be emitted after VICTORY');
  same(game.dash(), false, 'dash must be refused after VICTORY');
  same(game.spawnEnemy('chaser'), null, 'spawnEnemy must be refused after VICTORY');
  same(game.damageBoss(1), false, 'damageBoss must be refused after VICTORY');
  game.restart();
  same(snapshotOf(game).state, 'TITLE', 'restart must be accepted from VICTORY');
  return 'the boss appears only after three relays and victory requires three relays plus boss health exactly zero';
});

await clause('C17_entity_bounds', async () => {
  const game = newGame(29);
  game.start();
  const limit = snapshotOf(game).maxEnemies;
  for (let index = 0; index < limit * 2; index += 1) {
    const spawned = game.spawnEnemy(ENEMY_TYPES[index % ENEMY_TYPES.length]);
    const count = game.getState().enemies.length;
    need(count <= limit, 'the enemy count must never exceed maxEnemies, observed ' + show(count));
    if (index < limit) need(spawned !== null, 'spawn ' + index + ' must succeed below maxEnemies');
    else same(spawned, null, 'spawn ' + index + ' must be refused at maxEnemies');
  }
  same(snapshotOf(game).enemies.length, limit, 'the arena must hold exactly maxEnemies after saturation');
  same(game.spawnEnemy('not-an-archetype'), null, 'an unknown archetype must be refused');
  const player = snapshotOf(game).player;
  need(player.maxHealth > 0, 'maxHealth must be positive');
  same(player.health, player.maxHealth, 'a fresh run must start at full health');
  game.damagePlayer(1);
  same(snapshotOf(game).player.health, player.maxHealth - 1, 'damage must reduce health exactly');
  game.damagePlayer(-5);
  same(snapshotOf(game).player.health, player.maxHealth - 1, 'negative damage must never heal');
  game.damagePlayer(0);
  same(snapshotOf(game).player.health, player.maxHealth - 1, 'zero damage must change nothing');
  need(snapshotOf(game).relays.every((relay) => relay.charge >= 0 && relay.charge <= relay.fullCharge), 'every relay charge must stay bounded');
  const arena = snapshotOf(game).arena;
  need(
    snapshotOf(game).enemies.every((enemy) => enemy.x >= 0 && enemy.x <= arena.width && enemy.y >= 0 && enemy.y <= arena.height),
    'every enemy must stay inside the arena',
  );
  const position = snapshotOf(game).player;
  need(
    position.x >= 0 && position.x <= arena.width && position.y >= 0 && position.y <= arena.height,
    'the player must stay inside the arena',
  );
  game.damagePlayer(1000000000);
  const dead = snapshotOf(game);
  same(dead.player.health, 0, 'health must clamp to zero and never go negative');
  same(dead.state, 'GAME_OVER', 'clamped health must enter GAME_OVER');
  return 'enemy count, player health, relay charge and entity positions all stay inside their pinned bounds';
});

await clause('C18_enemy_archetypes', async () => {
  const game = newGame(31);
  const types = game.listEnemyTypes();
  need(Array.isArray(types), 'listEnemyTypes must return an array');
  need(types.every((type) => typeof type === 'string' && type.length > 0), 'archetype ids must be non-empty strings');
  need(new Set(types).size === types.length, 'archetype ids must be unique');
  deep(types.slice().sort(), ENEMY_TYPES.slice().sort(), 'exactly the three pinned archetypes must be exposed');
  const entities = projectTexts.get('src/entities.js') ?? (await readText('src/entities.js'));
  const undeclared = ENEMY_TYPES.filter((type) => !entities.includes(type));
  need(undeclared.length === 0, 'src/entities.js must define every archetype: ' + undeclared.join(', '));
  for (const type of ENEMY_TYPES) {
    const fresh = newGame(37);
    fresh.start();
    const spawned = fresh.spawnEnemy(type);
    needPlainObject(spawned, 'spawned ' + type);
    same(spawned.type, type, 'the spawned archetype must be ' + type);
    same(spawned.generation, 0, 'a directly spawned ' + type + ' must be generation zero');
    need(spawned.health > 0, 'a spawned ' + type + ' must be alive');
    same(snapshotOf(fresh).enemies.length, 1, 'spawning one ' + type + ' must add exactly one enemy');
    same(snapshotOf(fresh).enemies[0].type, type, 'the listed enemy must keep its archetype');
  }
  return 'exactly the chaser, shooter and splitter archetypes exist, are declared in entities and spawn independently';
});

// --------------------------------------------------------------------------
// Bounded report.
// --------------------------------------------------------------------------

const failed = results.filter((entry) => !entry.ok).map((entry) => entry.id);
const ok = failed.length === 0;
const report = {
  verifier: VERIFIER_ID,
  ok,
  clauseCount: results.length,
  failedClauses: failed,
  clauses: results,
  nonClaims: NON_CLAIMS,
};
let payload = JSON.stringify(report);
if (payload.length > OUTPUT_BOUND) {
  payload = JSON.stringify({
    verifier: VERIFIER_ID,
    ok,
    clauseCount: results.length,
    failedClauses: failed,
    clauses: results.map((entry) => ({ id: entry.id, ok: entry.ok, message: 'omitted for the output bound' })),
    nonClaims: NON_CLAIMS,
    truncated: true,
  });
}
console.log(payload);
if (ok) {
  console.log(SUCCESS_LINE);
  process.exitCode = 0;
} else {
  process.exitCode = 1;
}
"""

NEON_RELAY_VERIFIER_SOURCE_SHA256 = _sha256_text(NEON_RELAY_VERIFIER_SOURCE)
NEON_RELAY_MISSION_TEXT_SHA256 = _sha256_text(NEON_RELAY_MISSION_TEXT)
NEON_RELAY_COMPLETION_CONDITIONS_SHA256 = _sha256_text(NEON_RELAY_COMPLETION_CONDITIONS_TEXT)


__all__ = [
    "NEON_RELAY_COMPLETION_CONDITIONS_SHA256",
    "NEON_RELAY_COMPLETION_CONDITIONS_TEXT",
    "NEON_RELAY_DOMAIN_MODULE_PATHS",
    "NEON_RELAY_ENEMY_TYPES",
    "NEON_RELAY_FIXTURE_MARKER",
    "NEON_RELAY_MISSION_TEXT",
    "NEON_RELAY_MISSION_TEXT_SHA256",
    "NEON_RELAY_OPERATIONS",
    "NEON_RELAY_REQUIRED_COMMIT_MESSAGE",
    "NEON_RELAY_REQUIRED_MATERIAL_PATHS",
    "NEON_RELAY_STATES",
    "NEON_RELAY_VERIFIER_CLAUSE_IDS",
    "NEON_RELAY_VERIFIER_NON_CLAIMS",
    "NEON_RELAY_VERIFIER_SOURCE",
    "NEON_RELAY_VERIFIER_SOURCE_SHA256",
    "NEON_RELAY_VERIFIER_SUCCESS_LINE",
]
