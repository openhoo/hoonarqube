function Probe(done) {
  if (this.isMounted()) {
    done();
  }
}
