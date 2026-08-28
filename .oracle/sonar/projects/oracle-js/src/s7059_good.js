class Server {
  constructor() {
    this.ready = false;
  }

  async start() {
    await load();
  }
}
