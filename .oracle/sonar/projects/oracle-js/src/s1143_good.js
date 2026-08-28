function catchReturn(err) {
  try {
    a();
  } catch (e) {
    return e;
  }
}
