// S2612 good: strong SHA-256 digest instead of MD5/SHA-1.
const crypto = require("crypto");
const checksum = crypto.createHash("sha256").update(payload).digest("hex");
module.exports = { checksum };
