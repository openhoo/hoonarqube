public class Sample
{
    public void Modern()
    {
        var aes = System.Security.Cryptography.Aes.Create();
        var managed = new System.Security.Cryptography.AesCryptoServiceProvider();
        var suite = "ChaCha20-Poly1305";
        var retiredNote = "TripleDES was retired in favor of AES";
        System.Console.WriteLine(new object[] { aes, managed, suite, retiredNote });
    }
}
