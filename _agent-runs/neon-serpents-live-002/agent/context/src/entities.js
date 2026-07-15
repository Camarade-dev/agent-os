/** Entity definitions and helpers for Neon Serpents */

export const GRID_COLS = 32;
export const GRID_ROWS = 24;
export const TICK_MS = 120;

export const DIRECTION = {
  UP: { x: 0, y: -1 },
  DOWN: { x: 0, y: 1 },
  LEFT: { x: -1, y: 0 },
  RIGHT: { x: 1, y: 0 },
};

export const OPPOSITE = {
  UP: 'DOWN',
  DOWN: 'UP',
  LEFT: 'RIGHT',
  RIGHT: 'LEFT',
};

export const NEON_COLORS = [
  '#00f5ff',
  '#ff00aa',
  '#39ff14',
  '#ff6b00',
  '#bf00ff',
  '#ffff00',
];

export const GAME_STATE = {
  IDLE: 'idle',
  RUNNING: 'running',
  PAUSED: 'paused',
  OVER: 'over',
};

let nextEntityId = 1;

export function createId() {
  return nextEntityId++;
}

export function resetEntityIds() {
  nextEntityId = 1;
}

export function dirKey(dir) {
  for (const [key, val] of Object.entries(DIRECTION)) {
    if (val.x === dir.x && val.y === dir.y) {
      return key;
    }
  }
  return 'RIGHT';
}

export function wrapCoord(value, max) {
  if (value < 0) {
    return max - 1;
  }
  if (value >= max) {
    return 0;
  }
  return value;
}

export class Snake {
  constructor(options) {
    this.id = options.id ?? createId();
    this.name = options.name ?? 'Snake';
    this.color = options.color ?? NEON_COLORS[0];
    this.isPlayer = options.isPlayer ?? false;
    this.isBot = options.isBot ?? false;
    this.alive = true;
    this.score = 0;
    this.growPending = 0;
    this.direction = { ...(options.direction || DIRECTION.RIGHT) };
    this.nextDirection = { ...this.direction };
    this.segments = options.segments.map((s) => ({ x: s.x, y: s.y }));
  }

  head() {
    return this.segments[0];
  }

  setDirection(dir) {
    const currentKey = dirKey(this.direction);
    const newKey = dirKey(dir);
    if (OPPOSITE[currentKey] === newKey) {
      return;
    }
    this.nextDirection = { ...dir };
  }

  applyBufferedDirection() {
    const currentKey = dirKey(this.direction);
    const newKey = dirKey(this.nextDirection);
    if (OPPOSITE[currentKey] !== newKey) {
      this.direction = { ...this.nextDirection };
    }
  }

  move(wrapWalls) {
    if (!this.alive) {
      return;
    }
    this.applyBufferedDirection();
    const head = this.head();
    let nx = head.x + this.direction.x;
    let ny = head.y + this.direction.y;

    if (wrapWalls) {
      nx = wrapCoord(nx, GRID_COLS);
      ny = wrapCoord(ny, GRID_ROWS);
    }

    this.segments.unshift({ x: nx, y: ny });
    if (this.growPending > 0) {
      this.growPending -= 1;
    } else {
      this.segments.pop();
    }
  }

  grow(amount = 1) {
    this.growPending += amount;
    this.score += amount;
  }

  occupies(x, y) {
    return this.segments.some((s) => s.x === x && s.y === y);
  }

  hitsSelf() {
    const head = this.head();
    const body = this.segments.slice(1);
    return body.some((s) => s.x === head.x && s.y === head.y);
  }
}

export class Food {
  constructor(x, y) {
    this.x = x;
    this.y = y;
    this.pulse = 0;
  }

  tick() {
    this.pulse = (this.pulse + 0.15) % (Math.PI * 2);
  }
}

export function randomEmptyCell(occupancyFn) {
  const free = [];
  for (let y = 0; y < GRID_ROWS; y++) {
    for (let x = 0; x < GRID_COLS; x++) {
      if (!occupancyFn(x, y)) {
        free.push({ x, y });
      }
    }
  }
  if (free.length === 0) {
    return null;
  }
  return free[Math.floor(Math.random() * free.length)];
}

export function createPlayerSnake() {
  const cx = Math.floor(GRID_COLS / 4);
  const cy = Math.floor(GRID_ROWS / 2);
  return new Snake({
    name: 'You',
    color: NEON_COLORS[0],
    isPlayer: true,
    direction: DIRECTION.RIGHT,
    segments: [
      { x: cx, y: cy },
      { x: cx - 1, y: cy },
      { x: cx - 2, y: cy },
    ],
  });
}

export function createBotSnake(index) {
  const positions = [
    { x: Math.floor((GRID_COLS * 3) / 4), y: Math.floor(GRID_ROWS / 4), dir: DIRECTION.LEFT },
    { x: Math.floor(GRID_COLS / 2), y: Math.floor((GRID_ROWS * 3) / 4), dir: DIRECTION.UP },
    { x: Math.floor(GRID_COLS / 4), y: Math.floor((GRID_ROWS * 3) / 4), dir: DIRECTION.RIGHT },
  ];
  const pos = positions[index % positions.length];
  const segs = [
    { x: pos.x, y: pos.y },
    { x: pos.x - pos.dir.x, y: pos.y - pos.dir.y },
    { x: pos.x - pos.dir.x * 2, y: pos.y - pos.dir.y * 2 },
  ];
  return new Snake({
    name: 'Bot ' + (index + 1),
    color: NEON_COLORS[(index + 1) % NEON_COLORS.length],
    isBot: true,
    direction: { ...pos.dir },
    segments: segs,
  });
}
