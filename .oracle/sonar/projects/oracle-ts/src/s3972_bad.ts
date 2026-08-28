if (a) {
  b();
} else {
  c();
}
try {
  a();
} catch (e) {
  b(e);
} finally {
  c();
}
