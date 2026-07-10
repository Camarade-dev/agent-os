(() => {
  "use strict";

  const state = { value: "", valid: false, submitted: false, submitCount: 0 };
  const input = document.getElementById("name");
  const message = document.getElementById("validation-message");
  const banner = document.getElementById("submitted-banner");
  const form = document.getElementById("demo-form");

  function validate() {
    state.value = input.value;
    state.valid = state.value.trim().length >= 3;
    message.textContent = state.valid ? "Looks good." : "Enter at least 3 characters.";
    message.classList.toggle("valid", state.valid);
  }

  input.addEventListener("input", validate);

  form.addEventListener("submit", (event) => {
    // Local-only: never actually navigates or sends a network request.
    event.preventDefault();
    validate();
    if (state.valid) {
      state.submitted = true;
      state.submitCount += 1;
      banner.hidden = false;
    }
  });

  window.__FORM__ = {
    snapshot() {
      return {
        value: state.value,
        valid: state.valid,
        submitted: state.submitted,
        submitCount: state.submitCount,
      };
    },
  };

  validate();
})();
