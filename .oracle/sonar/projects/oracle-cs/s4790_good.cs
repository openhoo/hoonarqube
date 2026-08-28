public class Sample
{
    public byte[] Strong(byte[] data)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hmac = new System.Security.Cryptography.HMACSHA256();
        var note = "md5 and sha1 are retired for security purposes";
        return sha.ComputeHash(data);
    }
}
