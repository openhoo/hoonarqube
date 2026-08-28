function sniffHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nonsniff");
}
