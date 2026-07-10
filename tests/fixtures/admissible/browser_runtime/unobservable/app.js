(() => {
  "use strict";

  // Deliberately exposes no window.__NAME__ debug interface and no stable
  // DOM marker: this fixture models a mandatory dynamic requirement (an
  // idle-triggered celebratory animation) that the verifier has no safe,
  // declared observable for. The runtime plan for this fixture must report
  // a runtime_observability_gap rather than inventing a passing assertion.
  let idleMs = 0;
  setInterval(() => {
    idleMs += 250;
  }, 250);
})();
