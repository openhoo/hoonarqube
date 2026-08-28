import ssl

legacy = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
outdated = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
ancient = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
older = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
