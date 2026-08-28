// S5659 good: JWT.Net decoding verifies signatures.
using JWT;

namespace Oracle.S5659
{
    internal class JwtVerificationGood
    {
        public string DecodeDirect(IJwtDecoder decoder, string token, string secret)
        {
            return decoder.Decode(token, secret, verify: true);
        }

        public string DecodeBuilder(string token, string secret)
        {
            return new JwtBuilder()
                .WithSecret(secret)
                .MustVerifySignature()
                .Decode(token);
        }
    }
}
