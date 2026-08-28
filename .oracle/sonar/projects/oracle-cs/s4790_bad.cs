public class Sample
{
    public void Weak()
    {
        var md5 = System.Security.Cryptography.MD5.Create();
        var sha1 = System.Security.Cryptography.SHA1.Create();
        var keyed = new System.Security.Cryptography.HMACMD5();
        var legacy = new System.Security.Cryptography.SHA1CryptoServiceProvider();
        System.Console.WriteLine(new object[] { md5, sha1, keyed, legacy });
    }
}
