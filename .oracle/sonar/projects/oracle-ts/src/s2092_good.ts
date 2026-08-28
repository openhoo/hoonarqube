// S2092 good: 'secure' enabled alongside the other cookie flags.
function login(res) {
  res.cookie("sessionId", "abc123", { secure: true, httpOnly: true, path: "/" });
}
module.exports = { login };
