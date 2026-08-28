// S4817 bad: XPath evaluation entry point required.
const xpath = require("xpath");
const nodes = xpath.select(expression, document);
module.exports = { nodes };
