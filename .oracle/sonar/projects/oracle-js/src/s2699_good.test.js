// S2699 good: test case body asserts the outcome.
describe("cart", () => {
  it("adds an item", () => {
    cart.add("book");
    expect(cart.items).toContain("book");
  });
});
