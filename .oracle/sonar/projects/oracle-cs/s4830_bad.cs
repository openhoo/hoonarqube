public class Sample
{
    public void TrustEverything()
    {
        System.Net.ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true;
    }

    public void TrustCustomEverything(System.Net.Http.HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) => true;
    }
}
