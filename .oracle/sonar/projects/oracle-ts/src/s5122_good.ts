// S5122 good: cross-origin policy restricted to a trusted origin.
function enableCors(request) {
  return cors({ origin: "https://dashboard.example.com", methods: ["GET"] });
}
module.exports = { enableCors };
