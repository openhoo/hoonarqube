// S4818 good: TLS socket module instead of raw net/dgram.
const tls = require("tls");
const port = 8443;
module.exports = { tls, port };
