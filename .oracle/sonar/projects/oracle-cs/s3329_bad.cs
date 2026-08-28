using System.Security.Cryptography;

class CipherBox
{
    void Configure(Aes aes, Aes cipher)
    {
        aes.IV = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        cipher.IV = new byte[] { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    }

    ICryptoTransform Decrypt(Aes aes, byte[] key)
    {
        return aes.CreateDecryptor(key, new byte[] { 7, 9 });
    }
}
