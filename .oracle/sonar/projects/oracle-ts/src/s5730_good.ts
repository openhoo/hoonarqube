function securityHeaders(res) {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; upgrade-insecure-requests; frame-ancestors 'self'",
  );
}
