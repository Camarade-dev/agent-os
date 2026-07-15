/** Entry point for Neon Serpents */

import { Game } from './game.js';
import { Renderer } from './render.js';
import { DIRECTION, GAME_STATE, TICK_MS } from './entities.js';

const canvas = document.getElementById('game-canvas');
const scoreEl = document.getElementById('score');
const statusEl = document.getElementById('status');
const messageEl = document.getElementById('message');

const game = new Game();
const renderer = new Renderer(canvas);

let lastTime = 0;
let accumulator = 0;

const KEY_TO_DIRECTION = {
  ArrowUp: DIRECTION.UP,
  ArrowDown: DIRECTION.DOWN,
  ArrowLeft: DIRECTION.LEFT,
  ArrowRight: DIRECTION.RIGHT,
  w: DIRECTION.UP,
  W: DIRECTION.UP,
  s: DIRECTION.DOWN,
  S: DIRECTION.DOWN,
  a: DIRECTION.LEFT,
  A: DIRECTION.LEFT,
  d: DIRECTION.RIGHT,
  D: DIRECTION.RIGHT,
};

function updateHud() {
  scoreEl.textContent = String(game.playerScore());

  switch (game.state) {
    case GAME_STATE.RUNNING:
      statusEl.textContent = 'Playing';
      break;
    case GAME_STATE.PAUSED:
      statusEl.textContent = 'Paused';
      break;
    case GAME_STATE.OVER:
      statusEl.textContent = 'Game Over';
      break;
    default:
      statusEl.textContent = 'Ready';
      break;
  }
}

function updateMessage() {
  switch (game.state) {
    case GAME_STATE.IDLE:
      messageEl.textContent = 'Press Space or Enter to start.';
      break;
    case GAME_STATE.RUNNING:
      messageEl.textContent = 'Collect neon orbs. Avoid snakes and yourself.';
      break;
    case GAME_STATE.PAUSED:
      messageEl.textContent = 'Paused — press P to resume.';
      break;
    case GAME_STATE.OVER:
      messageEl.textContent = game.winnerText || 'Press Space or Enter to restart.';
      break;
    default:
      break;
  }
}

function setPlayerDirection(dir) {
  const player = game.playerSnake();
  if (player && player.alive && game.state === GAME_STATE.RUNNING) {
    player.setDirection(dir);
  }
}

function handleStartOrRestart() {
  if (game.state === GAME_STATE.IDLE || game.state === GAME_STATE.OVER) {
    game.start();
    updateHud();
    updateMessage();
  }
}

function handlePauseToggle() {
  if (game.state === GAME_STATE.RUNNING || game.state === GAME_STATE.PAUSED) {
    game.togglePause();
    updateHud();
    updateMessage();
  }
}

function onKeyDown(event) {
  const dir = KEY_TO_DIRECTION[event.key];
  if (dir) {
    event.preventDefault();
    setPlayerDirection(dir);
    return;
  }

  if (event.key === ' ' || event.key === 'Enter') {
    event.preventDefault();
    handleStartOrRestart();
    return;
  }

  if (event.key === 'p' || event.key === 'P') {
    event.preventDefault();
    handlePauseToggle();
  }
}

function frame(time) {
  if (!lastTime) {
    lastTime = time;
  }

  const delta = time - lastTime;
  lastTime = time;
  accumulator += delta;

  while (accumulator >= TICK_MS) {
    game.tick();
    accumulator -= TICK_MS;
  }

  updateHud();
  if (game.state === GAME_STATE.RUNNING || game.state === GAME_STATE.OVER) {
    updateMessage();
  }

  renderer.renderFrame(game);
  requestAnimationFrame(frame);
}

window.addEventListener('keydown', onKeyDown);
canvas.addEventListener('click', () => canvas.focus());

updateHud();
updateMessage();
renderer.renderFrame(game);
canvas.focus();
requestAnimationFrame(frame);
