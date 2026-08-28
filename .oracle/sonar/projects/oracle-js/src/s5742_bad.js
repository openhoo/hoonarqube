function ctHeaders(res) {
  res.setHeader("Expect-CT", "max-age=0, enforce");
}
