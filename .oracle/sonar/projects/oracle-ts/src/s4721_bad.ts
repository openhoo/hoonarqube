// S4721 bad: shell-interpreting child process call.
const { exec } = require("child_process");
exec("/usr/bin/git status --porcelain");
