// S5973 bad: nondeterministic value generated inside a test.
test("generates an id", () => {
  const id = Math.random().toString(36);
  render(id);
});
