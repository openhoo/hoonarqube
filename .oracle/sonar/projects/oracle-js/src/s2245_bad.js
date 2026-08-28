// S2245 bad: nondeterministic token derived from Math.random().
const token = Math.random().toString(36).slice(2);
module.exports = { token };
