const crypto = require("crypto");

const cipher = crypto.createCipheriv("aes-128-ecb", Buffer.alloc(16), null);

module.exports = cipher;
