const crypto = require("crypto");

const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12));

module.exports = cipher;
