public class Sample
{
    public bool Verify(System.Security.Cryptography.Xml.SignedXml signedXml, System.Security.Cryptography.RSA trustedKey)
    {
        return signedXml.CheckSignature(trustedKey);
    }
}
