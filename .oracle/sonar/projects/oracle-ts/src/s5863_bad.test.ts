// S5863 bad: assertion compares the expression with itself.
function checkName(user) {
  expect(user.name).to.equal(user.name);
}
