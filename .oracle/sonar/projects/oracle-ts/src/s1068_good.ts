class Session {
  private staleToken = "x";
  token() {
    return this.staleToken;
  }
}
new Session().token();
