class Session {
  private staleToken = "x";
  ping() {
    return 1;
  }
}
new Session().ping();
