// S5542 bad: ECB for AES and legacy RSA PKCS#1 v1.5 encryption.
using System.Security.Cryptography;

namespace Oracle.S5542
{
    internal class CiphersBad
    {
        public Aes Configure()
        {
            return new AesManaged
            {
                KeySize = 128,
                BlockSize = 128,
                Mode = CipherMode.ECB, // S5542
                Padding = PaddingMode.PKCS7,
            };
        }

        public byte[] Encrypt(byte[] data)
        {
            using var rsa = new RSACryptoServiceProvider();
            return rsa.Encrypt(data, false); // S5542
        }
    }
}
