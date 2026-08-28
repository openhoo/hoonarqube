// S4502 good: route ignore list left empty, CSRF stays active.
const csurf = require("csurf");
const protection = csurf({ ignoreRoutes: [] });
module.exports = { protection };
