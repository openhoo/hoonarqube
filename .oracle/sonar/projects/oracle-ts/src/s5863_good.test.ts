// S5863 good: assertion compares distinct expressions.
function checkName(user, account) {
  expect(user.name).to.equal(account.owner);
}
