import hashlib
import hmac

digest = hashlib.sha256(b"data").hexdigest()
mac = hmac.new(b"k", b"d", "sha256")
print(digest, mac)
