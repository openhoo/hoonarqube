// S5042 good: archive bytes inspected without extraction calls.
const entries = fs.readFileSync("bundle.zip");
module.exports = { entries };
