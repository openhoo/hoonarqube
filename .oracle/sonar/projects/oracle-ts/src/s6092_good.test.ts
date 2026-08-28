// S6092 good: each chai matcher gets its own assertion.
function verifyTags(tags) {
  expect(tags).to.include("alpha");
  expect(tags).to.contain("beta");
}
