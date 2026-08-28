function good() {
  if (a) {
    b();
  } else {
    c();
  }
  try {
    d();
  } catch (e) {
    f();
  } finally {
    g();
  }
  while (a) {
    h();
  }
}
