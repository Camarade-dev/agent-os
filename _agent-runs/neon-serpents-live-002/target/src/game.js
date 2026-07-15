/** Core game logic for Neon Serpents */

import {
  GAME_STATE,
  Food,
  randomEmptyCell,
  createPlayerSnake,
  createBotSnake,
  resetEntityIds,
} from './entities.js';
import { updateBots } from './bots.js';

export const BOT_COUNT = 2;
export const FOOD_COUNT = 3;
export const WRAP_WALLS = true;

export class Game {
  constructor() {
    this.state = GAME_STATE.IDLE;
    this.snakes = [];
    this.foods = [];
    this.winnerText = null;
  }

  playerSnake() {
    return this.snakes.find((s) => s.isPlayer) || null;
  }

  playerScore() {
    const player = this.playerSnake();
    return player ? player.score : 0;
  }

  isOccupied(x, y) {
    for (const food of this.foods) {
      if (food.x === x && food.y === y) {
        return true;
      }
    }
    for (const snake of this.snakes) {
      if (snake.occupies(x, y)) {
        return true;
      }
    }
    return false;
  }

  spawnFood() {
    const cell = randomEmptyCell((x, y) => this.isOccupied(x, y));
    if (cell) {
      this.foods.push(new Food(cell.x, cell.y));
    }
  }

  startNewRound() {
    resetEntityIds();
    this.snakes = [createPlayerSnake()];
    for (let i = 0; i < BOT_COUNT; i += 1) {
      this.snakes.push(createBotSnake(i));
    }
    this.foods = [];
    for (let i = 0; i < FOOD_COUNT; i += 1) {
      this.spawnFood();
    }
    this.winnerText = null;
    this.state = GAME_STATE.RUNNING;
  }

  start() {
    this.startNewRound();
  }

  togglePause() {
    if (this.state === GAME_STATE.RUNNING) {
      this.state = GAME_STATE.PAUSED;
      return;
    }
    if (this.state === GAME_STATE.PAUSED) {
      this.state = GAME_STATE.RUNNING;
    }
  }

  tick() {
    if (this.state !== GAME_STATE.RUNNING) {
      return;
    }

    updateBots(this, WRAP_WALLS);

    for (const snake of this.snakes) {
      if (snake.alive) {
        snake.move(WRAP_WALLS);
      }
    }

    this.resolveCollisions();
    this.collectFood();
    this.foods.forEach((food) => food.tick());

    const player = this.playerSnake();
    if (!player || !player.alive) {
      this.state = GAME_STATE.OVER;
      this.winnerText = this.buildResultMessage();
    }
  }

  resolveCollisions() {
    for (const snake of this.snakes) {
      if (snake.alive && snake.hitsSelf()) {
        snake.alive = false;
      }
    }

    const headGroups = new Map();
    for (const snake of this.snakes) {
      if (!snake.alive) {
        continue;
      }
      const head = snake.head();
      const key = head.x + ',' + head.y;
      if (!headGroups.has(key)) {
        headGroups.set(key, []);
      }
      headGroups.get(key).push(snake);
    }

    for (const group of headGroups.values()) {
      if (group.length <= 1) {
        continue;
      }
      const maxLen = Math.max(...group.map((s) => s.segments.length));
      const tiedLeaders = group.filter((s) => s.segments.length === maxLen);
      if (tiedLeaders.length > 1) {
        group.forEach((s) => {
          s.alive = false;
        });
      } else {
        group.forEach((s) => {
          if (s.segments.length < maxLen) {
            s.alive = false;
          }
        });
      }
    }

    for (const snake of this.snakes) {
      if (!snake.alive) {
        continue;
      }
      const head = snake.head();
      for (const other of this.snakes) {
        if (other.id === snake.id || !other.alive) {
          continue;
        }
        for (let i = 1; i < other.segments.length; i += 1) {
          const seg = other.segments[i];
          if (seg.x === head.x && seg.y === head.y) {
            snake.alive = false;
            break;
          }
        }
      }
    }
  }

  collectFood() {
    for (const snake of this.snakes) {
      if (!snake.alive) {
        continue;
      }
      const head = snake.head();
      for (let i = this.foods.length - 1; i >= 0; i -= 1) {
        const food = this.foods[i];
        if (food.x === head.x && food.y === head.y) {
          snake.grow();
          this.foods.splice(i, 1);
          this.spawnFood();
        }
      }
    }
  }

  buildResultMessage() {
    const player = this.playerSnake();
    const playerScore = player ? player.score : 0;

    if (player && player.alive) {
      return 'You survived! Score: ' + playerScore;
    }

    const sorted = [...this.snakes].sort((a, b) => b.score - a.score);
    const leader = sorted[0];

    if (leader && leader.isPlayer) {
      return 'Top score: ' + playerScore;
    }

    if (leader) {
      return leader.name + ' wins. Your score: ' + playerScore;
    }

    return 'Score: ' + playerScore;
  }
}
