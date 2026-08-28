// S2255 bad: Set-Cookie header written without HTTPS-only review.
function respond(response) {
  response.setHeader("Set-Cookie", "session=abc123; Path=/");
}
module.exports = { respond };
