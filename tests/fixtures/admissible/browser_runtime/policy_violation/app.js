(() => {
  "use strict";

  const state = { attempted: false };

  function triggerViolations() {
    state.attempted = true;

    // 1. External fetch -- must be aborted by the verifier before it leaves
    // the machine.
    fetch("https://example.invalid/external-fetch-attempt").catch(() => {});

    // 2. Popup -- must be denied/closed before it can load anything.
    window.open("https://example.invalid/popup-attempt", "_blank");

    // 3. Download -- must be denied.
    const link = document.createElement("a");
    link.href = "https://example.invalid/download-attempt.txt";
    link.download = "download-attempt.txt";
    document.body.appendChild(link);
    link.click();
  }

  document.getElementById("trigger").addEventListener("click", triggerViolations);

  window.__POLICY__ = {
    snapshot() {
      return { attempted: state.attempted };
    },
  };
})();
