// S4829 bad: standard input read under review.
process.stdin.setEncoding("utf8");
process.stdin.on("data", consume);
