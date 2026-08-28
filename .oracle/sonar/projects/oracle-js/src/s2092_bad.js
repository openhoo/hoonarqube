// S2092 bad: session cookie without the 'secure' option.
function login(res) {
  res.cookie("sessionId", "abc123", { httpOnly: true, path: "/" });
}
module.exports = { login };
