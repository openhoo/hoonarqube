class CipherBox
{
    void Configure(Aes aes, byte[] ivBuffer)
    {
        aes.IV = ivBuffer;
    }

    System.Security.Cryptography.ICryptoTransform Decrypt(Aes aes, byte[] masterKey, byte[] ivBuffer)
    {
        return aes.CreateDecryptor(masterKey, ivBuffer);
    }
}
