public class Sample
{
    public void Legacy()
    {
        var des = System.Security.Cryptography.DES.Create();
        var triple = System.Security.Cryptography.TripleDES.Create();
        var rc2 = System.Security.Cryptography.RC2.Create();
        var legacy = new System.Security.Cryptography.DESCryptoServiceProvider();
        var legacy3 = new System.Security.Cryptography.TripleDESCryptoServiceProvider();
        System.Console.WriteLine(new object[] { des, triple, rc2, legacy, legacy3 });
    }
}
