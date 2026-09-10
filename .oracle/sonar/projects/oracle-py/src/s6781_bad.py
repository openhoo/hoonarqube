import jwt

token = jwt.encode({"sub": "example-user"}, "s3cr3t-signing-key", algorithm="HS256")
