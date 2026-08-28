function withReturn() {
  try {
    a();
  } finally {
    return 1;
  }
}
