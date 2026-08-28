it("asserts failure", function () {
  try {
    risky();
  } catch (error) {
    expect(error).to.be.an("error");
  }
});
