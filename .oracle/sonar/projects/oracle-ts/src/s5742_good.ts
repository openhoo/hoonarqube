function ctHeaders(res) {
  res.setHeader("Expect-CT", "max-age=86400, enforce");
}
