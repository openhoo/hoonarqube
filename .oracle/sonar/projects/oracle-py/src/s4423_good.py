import ssl

modern = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
compatible = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
secure = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
