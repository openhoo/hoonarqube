it("handles failure", function () {
  try {
    risky();
  } catch (error) {
    console.log(error);
  }
});

it("asserts any error", function () {
  expect(() => risky()).to.throw();
});

it("asserts the base error", function () {
  expect(() => risky()).to.throw(Error);
});

it("asserts without a type", function () {
  assert.throws(() => risky());
});
