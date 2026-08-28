// S5542 good: authenticated AES and OAEP for RSA.
using System.Security.Cryptography;

namespace Oracle.S5542
{
    internal class CiphersGood
    {
        public byte[] Encrypt(byte[] data, byte[] key, byte[] nonce)
        {
            using var aes = new AesGcm(key);
            var encrypted = new byte[data.Length];
            var tag = new byte[16];
            aes.Encrypt(nonce, data, encrypted, tag);
            return encrypted;
        }

        public byte[] EncryptRsa(byte[] data)
        {
            using var rsa = new RSACryptoServiceProvider();
            return rsa.Encrypt(data, true);
        }
    }
}
