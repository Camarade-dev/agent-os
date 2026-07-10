(() => {
  "use strict";

  const ENTITY_COUNT = 6;
  const canvas = document.getElementById("stage");
  const ctx = canvas.getContext("2d");
  const overlay = document.getElementById("debug-overlay");
  const entityCountEl = document.getElementById("entity-count");

  const entities = Array.from({ length: ENTITY_COUNT }, (_, i) => ({
    x: 10 + i * 40,
    y: 90,
    vx: (i % 2 === 0 ? 1 : -1) * 1.5,
  }));
  const state = { tick: 0 };

  function step() {
    state.tick += 1;
    for (const entity of entities) {
      entity.x += entity.vx;
      if (entity.x < 0 || entity.x > canvas.width - 10) {
        entity.vx *= -1;
      }
    }
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#6cf";
    for (const entity of entities) {
      ctx.fillRect(entity.x, entity.y, 10, 10);
    }
    window.requestAnimationFrame(step);
  }

  const params = new URLSearchParams(window.location.search);
  if (params.get("debug") === "1") {
    overlay.hidden = false;
    entityCountEl.textContent = String(ENTITY_COUNT);
  }

  window.__SIM__ = {
    snapshot() {
      return {
        entityCount: entities.length,
        tick: state.tick,
        positions: entities.map((e) => Math.round(e.x)),
      };
    },
  };

  window.requestAnimationFrame(step);
})();
