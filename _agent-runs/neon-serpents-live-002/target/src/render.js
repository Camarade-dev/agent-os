/** Canvas rendering for Neon Serpents */

import { GRID_COLS, GRID_ROWS, GAME_STATE } from './entities.js';

export class Renderer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.cellW = canvas.width / GRID_COLS;
    this.cellH = canvas.height / GRID_ROWS;
  }

  clear() {
    const ctx = this.ctx;
    const canvas = this.canvas;
    ctx.fillStyle = '#12121f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    this.drawGrid();
  }

  drawGrid() {
    const ctx = this.ctx;
    const canvas = this.canvas;
    const cellW = this.cellW;
    const cellH = this.cellH;
    ctx.strokeStyle = 'rgba(0, 245, 255, 0.08)';
    ctx.lineWidth = 1;
    for (let x = 0; x <= GRID_COLS; x++) {
      ctx.beginPath();
      ctx.moveTo(x * cellW, 0);
      ctx.lineTo(x * cellW, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y <= GRID_ROWS; y++) {
      ctx.beginPath();
      ctx.moveTo(0, y * cellH);
      ctx.lineTo(canvas.width, y * cellH);
      ctx.stroke();
    }
  }

  drawFood(food) {
    if (!food) {
      return;
    }
    const ctx = this.ctx;
    const cellW = this.cellW;
    const cellH = this.cellH;
    const cx = food.x * cellW + cellW / 2;
    const cy = food.y * cellH + cellH / 2;
    const pulse = 0.6 + Math.sin(food.pulse) * 0.2;
    const radius = Math.min(cellW, cellH) * 0.35 * pulse;

    ctx.save();
    ctx.shadowColor = '#ff6b00';
    ctx.shadowBlur = 12;
    ctx.fillStyle = '#ff6b00';
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.fillStyle = '#ffe066';
    ctx.beginPath();
    ctx.arc(cx, cy, radius * 0.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  }

  drawSnake(snake) {
    if (!snake.segments.length) {
      return;
    }
    const ctx = this.ctx;
    const cellW = this.cellW;
    const cellH = this.cellH;
    const pad = 2;

    snake.segments.forEach((seg, i) => {
      const x = seg.x * cellW + pad;
      const y = seg.y * cellH + pad;
      const w = cellW - pad * 2;
      const h = cellH - pad * 2;
      const alpha = snake.alive ? 1 : 0.35;

      ctx.save();
      ctx.globalAlpha = alpha;
      ctx.shadowColor = snake.color;
      ctx.shadowBlur = i === 0 ? 14 : 8;
      ctx.fillStyle = snake.color;
      const radius = i === 0 ? 4 : 3;
      this.roundRect(x, y, w, h, radius);
      ctx.fill();

      if (i === 0) {
        ctx.fillStyle = '#ffffff';
        ctx.globalAlpha = alpha * 0.9;
        const eyeR = Math.min(w, h) * 0.12;
        ctx.beginPath();
        ctx.arc(x + w * 0.65, y + h * 0.35, eyeR, 0, Math.PI * 2);
        ctx.arc(x + w * 0.65, y + h * 0.65, eyeR, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.restore();
    });

    if (snake.name) {
      const head = snake.segments[0];
      ctx.save();
      ctx.font = '10px monospace';
      ctx.fillStyle = snake.alive ? snake.color : '#666666';
      ctx.textAlign = 'center';
      ctx.fillText(snake.name, head.x * cellW + cellW / 2, head.y * cellH - 4);
      ctx.restore();
    }
  }

  roundRect(x, y, w, h, r) {
    const ctx = this.ctx;
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  drawOverlay(state, playerScore, winnerText) {
    const canvas = this.canvas;
    if (state === GAME_STATE.IDLE) {
      this.drawCenterText('NEON SERPENTS', '#00f5ff', 28);
      this.drawCenterText('Press Space or Enter to Start', '#8899aa', 14, canvas.height / 2 + 36);
      return;
    }
    if (state === GAME_STATE.PAUSED) {
      const ctx = this.ctx;
      ctx.fillStyle = 'rgba(0, 0, 0, 0.55)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      this.drawCenterText('PAUSED', '#ff00aa', 32);
      this.drawCenterText('Press P to Resume', '#8899aa', 14, canvas.height / 2 + 32);
      return;
    }
    if (state === GAME_STATE.OVER) {
      const ctx = this.ctx;
      ctx.fillStyle = 'rgba(0, 0, 0, 0.65)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      this.drawCenterText('GAME OVER', '#ff0066', 32);
      const msg = winnerText || ('Score: ' + playerScore);
      this.drawCenterText(msg, '#39ff14', 16, canvas.height / 2 + 28);
      this.drawCenterText('Press Space or Enter to Restart', '#8899aa', 13, canvas.height / 2 + 56);
    }
  }

  drawCenterText(text, color, size, yOffset) {
    const ctx = this.ctx;
    const canvas = this.canvas;
    const y = yOffset !== undefined ? yOffset : canvas.height / 2;
    ctx.save();
    ctx.font = 'bold ' + size + 'px "Segoe UI", system-ui, sans-serif';
    ctx.fillStyle = color;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.shadowColor = color;
    ctx.shadowBlur = 12;
    ctx.fillText(text, canvas.width / 2, y);
    ctx.restore();
  }

  renderFrame(game) {
    this.clear();
    game.foods.forEach((f) => this.drawFood(f));
    game.snakes.forEach((s) => this.drawSnake(s));
    this.drawOverlay(game.state, game.playerScore(), game.winnerText);
  }
}
