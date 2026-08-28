// S4502 bad: CSRF protection disabled for explicit routes.
const csurf = require("csurf");
const protection = csurf({ ignoreRoutes: ["/webhooks/payment"] });
module.exports = { protection };
