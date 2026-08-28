// S5247 good: automatic escaping stays enabled.
const nunjucks = require("nunjucks");
nunjucks.configure({ autoescape: true });
module.exports = { nunjucks };
