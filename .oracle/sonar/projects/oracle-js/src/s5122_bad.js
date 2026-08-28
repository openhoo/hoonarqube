// S5122 bad: wildcard cross-origin resource sharing policy.
function enableCors(request) {
  return cors({ origin: "*", methods: ["GET"] });
}
module.exports = { enableCors };
