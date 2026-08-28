it("handles failure", function () {
  try {
    risky();
  } catch (error) {
    console.log(error);
  }
});
