(() => {
  "use strict";

  const state = { count: 0, resets: 0 };
  const countEl = document.getElementById("count");

  function render() {
    countEl.textContent = String(state.count);
  }

  document.getElementById("increment").addEventListener("click", () => {
    state.count += 1;
    render();
  });

  document.getElementById("reset").addEventListener("click", () => {
    state.count = 0;
    state.resets += 1;
    render();
  });

  window.addEventListener("keydown", (event) => {
    if (event.key === "r" || event.key === "R") {
      state.count = 0;
      state.resets += 1;
      render();
    }
  });

  window.__COUNTER__ = {
    snapshot() {
      return { count: state.count, resets: state.resets };
    },
  };

  render();
})();
