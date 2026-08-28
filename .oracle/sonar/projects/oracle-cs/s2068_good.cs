class S2068Good
{
    private string userName;

    void Connect(string password)
    {
        var user = "admin";
        this.userName = user;
    }

    string LookupSecret()
    {
        return System.Environment.GetEnvironmentVariable("DB_PASSWD") ?? "";
    }
}
