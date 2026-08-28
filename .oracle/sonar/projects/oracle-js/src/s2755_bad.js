// S2755 bad: XML parser with entity substitution enabled.
const libxmljs = require("libxmljs");
const doc = libxmljs.parseXmlString(xmlText, { noent: true, noblanks: true });
module.exports = { doc };
