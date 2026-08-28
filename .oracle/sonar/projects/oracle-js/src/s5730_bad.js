function securityHeaders(res) {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
}
