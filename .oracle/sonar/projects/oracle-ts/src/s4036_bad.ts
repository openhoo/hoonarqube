// S4036 bad: bare executable name resolved through PATH.
const { spawn } = require("child_process");
spawn("openssl", ["version"]);
