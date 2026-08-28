// S4790 good: modern hash algorithm outside the deprecated family.
const crypto = require("crypto");
const digest = crypto.createHash("sha3-256").update(blob).digest();
module.exports = { digest };
