// S2755 good: entity substitution disabled via noxxe.
const libxmljs = require("libxmljs");
const doc = libxmljs.parseXmlString(xmlText, {
  noent: false,
  noxxe: true,
  noblanks: true,
});
module.exports = { doc };
