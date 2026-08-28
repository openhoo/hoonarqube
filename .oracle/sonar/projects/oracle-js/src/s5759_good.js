function clientIp(req) {
  return req.socket.remoteAddress;
}
