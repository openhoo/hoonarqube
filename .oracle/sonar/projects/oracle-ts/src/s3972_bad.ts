if (a) {
  b();
} if (b) {
  c();
} if (c) {
  d();
}
if (a) {
  b();
}
if (b) {
  c();
} if (d) {
  e();
}
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
