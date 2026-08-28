function read(setting, fallback) {
  with (setting) {
    return value || fallback;
  }
}
