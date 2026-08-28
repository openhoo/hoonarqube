// S5659 bad: JWT.Net decoding without signature verification.
using JWT;

namespace Oracle.S5659
{
    internal class JwtVerificationBad
    {
        public string DecodeDirect(IJwtDecoder decoder, string token, string secret)
        {
            return decoder.Decode(token, secret, verify: false); // S5659
        }

        public string DecodeBuilder(string token, string secret)
        {
            return new JwtBuilder()
                .WithSecret(secret)
                .Decode(token); // S5659
        }
    }
}
