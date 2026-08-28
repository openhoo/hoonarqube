// S5247 bad: template engine configured with autoescaping disabled.
const nunjucks = require("nunjucks");
nunjucks.configure({ autoescape: false });
module.exports = { nunjucks };
