function route(mode, flag) {
  if (mode === 'fast') {
    runFast();
  } else {
    if (flag) {
      runSlow();
    }
  }
}
