using System.Security.Cryptography;
class Hasher
{
    void Weak(string password, byte[] salt)
    {
        var defaults = new Rfc2898DeriveBytes(password, salt);
        var fewIterations = new Rfc2898DeriveBytes(password, salt, 10_000, HashAlgorithmName.SHA256);
        var oldDigest = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA1);
    }
}
