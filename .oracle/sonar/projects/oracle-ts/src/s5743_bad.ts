function prefetchHeaders(res) {
  res.setHeader("X-DNS-Prefetch-Control", "on");
}
