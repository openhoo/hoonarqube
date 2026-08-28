class LoggingSetup
{
    public static void Configure()
    {
        XmlConfigurator.Configure(new System.IO.FileInfo("log.config"));
    }
}
