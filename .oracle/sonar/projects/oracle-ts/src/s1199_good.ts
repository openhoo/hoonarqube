function work() {
  const value = prepare();
  {
    let value = prepare();
    use(value);
  }
  use(value);
}
