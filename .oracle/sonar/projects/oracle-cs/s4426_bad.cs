// S4426 bad: legacy providers and undersized keys.
using System.Security.Cryptography;

namespace Oracle.S4426
{
    internal class WeakKeysBad
    {
        public byte[] Seal(byte[] data)
        {
            using var rsa = new RSACryptoServiceProvider(); // S4426
            rsa.KeySize = 1024; // S4426
            return rsa.Encrypt(data, true);
        }

        public byte[] LegacySign(byte[] data)
        {
            using var dsa = new DSACryptoServiceProvider(); // S4426
            dsa.KeySize = 512; // S4426
            return dsa.SignData(data);
        }
    }
}
