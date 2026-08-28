// S4426 good: ECDH keys over a modern curve.
const crypto = require("crypto");
const exchange = crypto.createECDH("prime256v1");
module.exports = { exchange };
