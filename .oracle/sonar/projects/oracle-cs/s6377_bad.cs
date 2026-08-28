public class Sample
{
    public void Verify(System.Security.Cryptography.Xml.SignedXml signedXml)
    {
        signedXml.CheckSignature();
    }
}
