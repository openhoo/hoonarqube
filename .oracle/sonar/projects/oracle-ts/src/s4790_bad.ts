// S4790 bad: deprecated MD4 hash family usage.
const crypto = require("crypto");
const digest = crypto.createHash("md4").update(blob).digest();
module.exports = { digest };
