// S4426 good: modern providers and adequate key sizes.
using System.Security.Cryptography;

namespace Oracle.S4426
{
    internal class StrongKeysGood
    {
        public RSA CreateRsa()
        {
            var rsa = RSA.Create(4096); // factory over the modern provider
            rsa.KeySize = 4096; // at least 2048 bits
            return rsa;
        }

        public ECDsa CreateSigningKey()
        {
            return ECDsa.Create(ECCurve.NamedCurves.nistP384);
        }
    }
}
