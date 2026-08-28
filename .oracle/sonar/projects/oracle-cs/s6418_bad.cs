class S6418Bad
{
    private const string ApiKey = "sk-a1B2c3D4e5F6g7H8";

    void Send()
    {
        var authToken = "Zk!9mQ2#vLp8$wXz";
        Use(ApiKey, authToken);
    }

    void Use(string key, string token) { }
}
