using System.Security.Authentication;

public class Sample
{
    public void Deprecated()
    {
        var ssl2 = SslProtocols.Ssl2;
        var ssl3 = SslProtocols.Tls;
        var tls11 = System.Security.Authentication.SslProtocols.Tls11;
        var netSsl3 = System.Net.SecurityProtocolType.Ssl3;
        var legacy = SslProtocols.Default;
        _ = ssl2 | ssl3 | tls11 | legacy;
        _ = netSsl3;
    }
}
