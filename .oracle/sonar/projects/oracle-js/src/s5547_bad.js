const crypto = require("crypto");

const cipher = crypto.createCipheriv("des-ede3-cbc", Buffer.alloc(24), Buffer.alloc(8));

module.exports = cipher;
