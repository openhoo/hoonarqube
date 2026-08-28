using System.Security.Authentication;

public class Sample
{
    public void Modern()
    {
        var tls12 = SslProtocols.Tls12;
        var tls13 = System.Security.Authentication.SslProtocols.Tls13;
        var none = SslProtocols.None;
        var systemDefault = System.Net.SecurityProtocolType.SystemDefault;
        _ = tls12 | tls13 | none;
        _ = systemDefault;
    }
}
