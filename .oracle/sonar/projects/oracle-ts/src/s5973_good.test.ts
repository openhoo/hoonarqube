// S5973 good: deterministic values inside the test body.
test("renders a fixed id", () => {
  render("fixed-id");
  expect(document.title).toBe("ok");
});
