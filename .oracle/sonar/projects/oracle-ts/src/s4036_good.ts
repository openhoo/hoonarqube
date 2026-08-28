// S4036 good: full executable path given instead of a PATH lookup.
const { spawn } = require("child_process");
spawn("/usr/bin/openssl", ["version"]);
