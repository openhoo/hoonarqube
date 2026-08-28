class S1075Good
{
    string Relative() { return "/api/v1/orders"; }

    string HostOnly() { return "api.example.com"; }

    string Configured() { return System.Configuration.ConfigurationManager.AppSettings["endpoint"]; }
}
