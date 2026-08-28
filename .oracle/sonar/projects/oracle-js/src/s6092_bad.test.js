// S6092 bad: over-chained chai assertions in one expression.
function verifyTags(tags) {
  expect(tags).to.include("alpha").and.contain("beta");
}
