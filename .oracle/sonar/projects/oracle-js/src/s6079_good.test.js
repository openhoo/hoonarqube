// S6079 good: assertion precedes the done() invocation.
it("stops the server", function (done) {
  expect(server.running).toBe(true);
  server.close(done);
});
