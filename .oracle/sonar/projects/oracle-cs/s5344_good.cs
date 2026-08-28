using System.Security.Cryptography;
class Deriver
{
    byte[] Derive(string password, byte[] salt)
    {
        var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        return kdf.GetBytes(32);
    }
}
