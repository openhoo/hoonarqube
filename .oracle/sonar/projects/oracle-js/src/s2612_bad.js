// S2612 bad: weak MD5 digest for a checksum.
const crypto = require("crypto");
const checksum = crypto.createHash("md5").update(payload).digest("hex");
module.exports = { checksum };
