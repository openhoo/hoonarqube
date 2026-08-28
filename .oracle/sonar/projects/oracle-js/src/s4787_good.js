// S4787 good: no encryption API in the call graph.
const crypto = require("crypto");
const tag = crypto.randomBytes(16).toString("hex");
module.exports = { tag };
