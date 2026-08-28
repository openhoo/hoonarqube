function transportHeaders(res) {
  res.setHeader("Strict-Transport-Security", "max-age=0");
}
