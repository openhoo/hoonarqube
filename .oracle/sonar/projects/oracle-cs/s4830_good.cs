public class Sample
{
    public void ValidateChain()
    {
        System.Net.ServicePointManager.ServerCertificateValidationCallback =
            (sender, certificate, chain, errors) =>
                errors == System.Net.Security.SslPolicyErrors.None && certificate != null;
    }

    public void ValidateCustomChain(System.Net.Http.HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback =
            (request, certificate, chain, errors) =>
                errors == System.Net.Security.SslPolicyErrors.None;
    }
}
