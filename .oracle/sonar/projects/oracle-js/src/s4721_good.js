// S4721 good: argument-vector launch without a shell interpreter.
const { execFile } = require("child_process");
execFile("/usr/bin/git", ["status", "--porcelain"]);
