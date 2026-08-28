// S2255 good: unrelated security header, no Set-Cookie write.
function respond(response) {
  response.setHeader("X-Frame-Options", "DENY");
}
module.exports = { respond };
