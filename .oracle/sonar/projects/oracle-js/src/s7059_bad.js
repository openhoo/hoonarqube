class Server {
  constructor() {
    const pending = (async () => load())();
    void pending;
  }
}
