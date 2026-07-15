/** Bot AI for Neon Serpents */

import { DIRECTION, GRID_COLS, GRID_ROWS, wrapCoord } from './entities.js';

const DIRECTIONS = [DIRECTION.UP, DIRECTION.DOWN, DIRECTION.LEFT, DIRECTION.RIGHT];

function wrapDelta(from, to, max) {
  let delta = to - from;
  const half = max / 2;
  if (delta > half) {
    delta -= max;
  }
  if (delta < -half) {
    delta += max;
  }
  return delta;
}

function manhattanWrapped(ax, ay, bx, by) {
  const dx = Math.abs(wrapDelta(ax, bx, GRID_COLS));
  const dy = Math.abs(wrapDelta(ay, by, GRID_ROWS));
  return dx + dy;
}

function nearestFood(head, foods) {
  if (!foods.length) {
    return null;
  }

  let best = null;
  let bestDist = Infinity;

  for (const food of foods) {
    const dist = manhattanWrapped(head.x, head.y, food.x, food.y);
    if (dist < bestDist) {
      bestDist = dist;
      best = food;
    }
  }

  return best;
}

function directionToward(head, target) {
  const dx = wrapDelta(head.x, target.x, GRID_COLS);
  const dy = wrapDelta(head.y, target.y, GRID_ROWS);

  if (Math.abs(dx) > Math.abs(dy)) {
    return dx > 0 ? DIRECTION.RIGHT : DIRECTION.LEFT;
  }

  if (Math.abs(dy) > 0) {
    return dy > 0 ? DIRECTION.DOWN : DIRECTION.UP;
  }

  return null;
}

function nextCell(head, dir, wrapWalls) {
  let nx = head.x + dir.x;
  let ny = head.y + dir.y;

  if (wrapWalls) {
    nx = wrapCoord(nx, GRID_COLS);
    ny = wrapCoord(ny, GRID_ROWS);
  }

  return { x: nx, y: ny };
}

function isOccupiedBySnake(game, x, y, selfId) {
  for (const snake of game.snakes) {
    if (!snake.alive) {
      continue;
    }

    const isSelf = snake.id === selfId;
    const segments = isSelf ? snake.segments.slice(0, -1) : snake.segments;

    if (segments.some((seg) => seg.x === x && seg.y === y)) {
      return true;
    }
  }

  return false;
}

function safeDirections(game, snake, wrapWalls) {
  const head = snake.head();

  return DIRECTIONS.filter((dir) => {
    const cell = nextCell(head, dir, wrapWalls);

    if (!wrapWalls) {
      if (cell.x < 0 || cell.x >= GRID_COLS || cell.y < 0 || cell.y >= GRID_ROWS) {
        return false;
      }
    }

    return !isOccupiedBySnake(game, cell.x, cell.y, snake.id);
  });
}

export function updateBots(game, wrapWalls = true) {
  for (const snake of game.snakes) {
    if (!snake.isBot || !snake.alive) {
      continue;
    }

    const head = snake.head();
    const options = safeDirections(game, snake, wrapWalls);

    if (options.length === 0) {
      continue;
    }

    const food = nearestFood(head, game.foods);
    let choice = options[Math.floor(Math.random() * options.length)];

    if (food) {
      const preferred = directionToward(head, food);
      if (preferred && options.some((dir) => dir.x === preferred.x && dir.y === preferred.y)) {
        choice = preferred;
      }
    }

    snake.setDirection(choice);
  }
}
