// S2245 good: deterministic randomness source instead of Math.random().
const crypto = require("crypto");
const token = crypto.randomUUID();
module.exports = { token };
