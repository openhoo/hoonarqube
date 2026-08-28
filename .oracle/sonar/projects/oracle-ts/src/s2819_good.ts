// S2819 good: handler validates event.origin before acting.
window.addEventListener("message", (event) => {
  if (event.origin !== "https://portal.example.com") return;
  applyRemoteCommand(event.data);
});
