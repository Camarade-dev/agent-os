const canvas = document.getElementById('board');
const ctx = canvas.getContext('2d');
const scoreEl = document.getElementById('score');
const SIZE = 240;
const STEP = 10;
let x = 115;
let y = 115;
let score = 0;

function reset() {
  x = 115;
  y = 115;
  score = 0;
  updateScore();
}

function updateScore() {
  if (scoreEl) scoreEl.textContent = String(score);
}

window.addEventListener('keydown', (event) => {
  if (event.key === 'r' || event.key === 'R') {
    reset();
    return;
  }
  const before = x + y;
  if (event.key === 'ArrowLeft' || event.key === 'a' || event.key === 'A') x = Math.max(0, x - STEP);
  if (event.key === 'ArrowRight' || event.key === 'd' || event.key === 'D') x = Math.min(SIZE - STEP, x + STEP);
  if (event.key === 'ArrowUp' || event.key === 'w' || event.key === 'W') y = Math.max(0, y - STEP);
  if (event.key === 'ArrowDown' || event.key === 's' || event.key === 'S') y = Math.min(SIZE - STEP, y + STEP);
  if (x + y !== before) score += 1;
  updateScore();
});

function draw() {
  ctx.clearRect(0, 0, SIZE, SIZE);
  ctx.fillStyle = '#ff6b6b';
  ctx.fillRect(x, y, STEP, STEP);
  requestAnimationFrame(draw);
}

reset();
draw();
