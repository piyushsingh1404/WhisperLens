// public/js/ui.js

// Auto-hide flash messages after 3s
document.addEventListener("DOMContentLoaded", () => {
  const toast = document.querySelector(".toast");
  if (toast) {
    setTimeout(() => {
      toast.classList.add("fade-out");
      setTimeout(() => toast.remove(), 500);
    }, 3000);
  }
});

// Password visibility toggle
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("toggle-password")) {
    const input = document.querySelector(`#${e.target.dataset.target}`);
    if (input) {
      if (input.type === "password") {
        input.type = "text";
        e.target.textContent = "🙈";
      } else {
        input.type = "password";
        e.target.textContent = "👁️";
      }
    }
  }
});
