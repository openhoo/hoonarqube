import ssl

requests.get(url, verify=False)
ctx = ssl._create_unverified_context()
ctx.verify_mode = ssl.CERT_NONE
