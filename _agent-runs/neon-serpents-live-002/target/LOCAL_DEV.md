# Neon Serpents — Local Development

Neon Serpents is a self-contained browser game built with plain HTML, CSS, and JavaScript. No build step or external dependencies are required.

## Opening the Game

Open `index.html` in a modern web browser. The entry point loads `src/main.js` as an ES module.

For local development with ES modules, you may serve the project directory over HTTP. Example loopback URL (documentation only):

http://localhost:8080/

Then open `index.html` from that server.

Some browsers restrict ES module loading from the filesystem. If modules fail to load when opening the file directly, use a local HTTP server as described below.

## Project Layout

| Path | Purpose |
|------|---------|
| `index.html` | Game shell and controls panel |
| `style.css` | Neon-themed layout and typography |
| `src/main.js` | Entry point, input handling, game loop |
| `src/game.js` | Game state, collisions, scoring |
| `src/entities.js` | Snake, food, and grid helpers |
| `src/bots.js` | Bot snake AI |
| `src/render.js` | Canvas rendering |

## Keyboard Controls

| Key | Action |
|-----|--------|
| `W` or `↑` | Move up |
| `S` or `↓` | Move down |
| `A` or `←` | Move left |
| `D` or `→` | Move right |
| `Space` or `Enter` | Start or restart |
| `P` | Pause or resume |

Click the game canvas once to give it keyboard focus before playing.

## Gameplay

- Control the cyan snake labeled **You**.
- Collect glowing orbs to grow and increase your score.
- The arena wraps at the edges.
- Avoid colliding with other snakes and yourself.
- Two bot snakes compete for food.

## Serving Locally (Optional)

Python 3:

```
python -m http.server 8080
```

Then visit the loopback URL above and open `index.html`.

These commands are optional conveniences for local development only.
