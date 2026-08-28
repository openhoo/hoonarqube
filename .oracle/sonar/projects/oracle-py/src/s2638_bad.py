class Client:
    def connect(self, host, port=8080):
        return host


class TlsClient(Client):
    def connect(self, server, port=8080):
        return server
