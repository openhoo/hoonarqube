class Client:
    def connect(self, host, port=8080):
        return host


class TlsClient(Client):
    def connect(self, host, port=8080, timeout=None):
        return host


class UdpClient(Client):
    def connect(self, host, port=8080):
        return host
