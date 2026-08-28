// S2819 bad: message handler never consults event.origin.
window.addEventListener("message", (event) => {
  applyRemoteCommand(event.data);
});
