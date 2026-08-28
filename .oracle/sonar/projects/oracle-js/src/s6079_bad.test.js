// S6079 bad: statements scheduled after the done() invocation.
it("starts the server", function (done) {
  server.listen(0);
  done();
  server.close();
});
