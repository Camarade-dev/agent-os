(() => {
  "use strict";

  const canvas = document.getElementById("stage");
  const ctx = canvas.getContext("2d");

  const state = { frame: 0, x: 10, paused: false, running: false, loopStarts: 0, restarts: 0 };
  let rafHandle = null;

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#6cf";
    ctx.fillRect(state.x, 90, 20, 20);
  }

  function tick() {
    if (!state.running) {
      return;
    }
    if (!state.paused) {
      state.frame += 1;
      state.x = 10 + (state.frame % 280);
      draw();
    }
    rafHandle = window.requestAnimationFrame(tick);
  }

  function startLoop() {
    // Guard against duplicate loops: never schedule a second RAF chain
    // while one is already running.
    if (state.running) {
      return;
    }
    state.running = true;
    state.loopStarts += 1;
    rafHandle = window.requestAnimationFrame(tick);
  }

  function stopLoop() {
    state.running = false;
    if (rafHandle !== null) {
      window.cancelAnimationFrame(rafHandle);
      rafHandle = null;
    }
  }

  function togglePause() {
    state.paused = !state.paused;
  }

  function restart() {
    state.frame = 0;
    state.x = 10;
    state.restarts += 1;
    startLoop(); // no-op if already running -- this is the duplicate-loop guard under test
  }

  window.addEventListener("keydown", (event) => {
    if (event.key === "p" || event.key === "P") {
      togglePause();
    } else if (event.key === "r" || event.key === "R") {
      restart();
    }
  });

  window.__LOOP__ = {
    snapshot() {
      return {
        frame: state.frame,
        paused: state.paused,
        running: state.running,
        loopStarts: state.loopStarts,
        restarts: state.restarts,
      };
    },
  };

  draw();
  startLoop();
})();
