// S4787 bad: direct encryption API usage under review.
const crypto = require("crypto");
const sealed = crypto.publicEncrypt(peerPublicKey, payload);
module.exports = { sealed };
