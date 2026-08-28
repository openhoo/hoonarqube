// S4426 bad: ECDH keys generated over a weak curve.
const crypto = require("crypto");
const exchange = crypto.createECDH("secp192r1");
module.exports = { exchange };
